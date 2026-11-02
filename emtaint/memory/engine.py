"""Python P5 reference memory, using frozen Memory-Semantics-v1 descriptors.

Definitions are persistent. Reads stay MemoryRead(version, location) leaves;
byte definitions are resolved on demand, never nested into an input Load AST.
Distinct root IDs alone are not evidence of distinct concrete storage.
"""
from dataclasses import replace
import hashlib

from emtaint.core import MemoryObject, Completeness, Endian
from emtaint.core.contracts import (Assessment, Precision, SemanticBudgets, MemoryVersionId,
    MemoryLocationId, AccessPathId, ValueType, TypeKind, same_scope)
from emtaint.analysis.sse.dag import SymbolicExprDAG
from .access_path import AccessPath, Offset, Deref, Index, UnknownOffset, modular_offset
from .state import (MemoryLocation, AliasResult, AliasKind, UpdateKind, InitialMemory,
    WriteMemory, JoinMemory, JoinInput, HavocMemory, MemoryVersion, ReadMemory,
    SymbolicOp, MemorySnapshot, select_update_policy)
from .abstract_heap import HeapObject, HeapCell, ObjectCardinality, ObjectLifetime
from .query_port import (QueryBudget, ReadResult, WriteResult, PointsToResult, DefinitionResult)
from .policies import Accounting, BudgetExceeded


def token(value):
    return hashlib.sha256(repr(value).encode('utf8')).hexdigest()[:32]


def over(reason, incomplete=False):
    return Assessment(Completeness.INCOMPLETE if incomplete else Completeness.COMPLETE,
        Precision.OVER_APPROX, (reason,), diagnostics=(reason,) if incomplete else ())


def combine(assessments):
    assessments = tuple(assessments)
    loss = tuple(dict.fromkeys(x for a in assessments for x in a.precision_loss))
    unsupported = tuple(dict.fromkeys(x for a in assessments for x in a.unsupported_ops))
    diagnostics = tuple(dict.fromkeys(x for a in assessments for x in a.diagnostics))
    complete = all(a.status == Completeness.COMPLETE for a in assessments)
    return Assessment(Completeness.COMPLETE if complete else Completeness.INCOMPLETE,
        Precision.OVER_APPROX if loss else Precision.EXACT if complete else Precision.INCOMPLETE,
        loss, unsupported, diagnostics or (() if complete else ('Incomplete input',)))


class PythonMemoryEngine:
    @property
    def origins(self):return self._origins

    @origins.setter
    def origins(self, values):
        values=tuple(values)
        indexed={o.id:o for o in values}
        if len(indexed)!=len(values):raise ValueError('Duplicate memory origin identity')
        self._origins, self._origin_index=values, indexed

    def origin_record(self, origin):
        self._origin(origin)
        return self._origin_index[origin]

    def __init__(self, scope, architecture, origins, budgets=SemanticBudgets()):
        self.scope, self.architecture, self.origins, self.budgets = scope, architecture, tuple(origins), budgets
        if architecture.byte_bits != 8 or not self.origins:
            raise ValueError('Octet architecture and explicit origins required')
        self.accounting = Accounting(budgets)
        self.dag = SymbolicExprDAG(scope, self.accounting)
        self.objects, self.roots, self.object_facts = {}, {}, {}
        self.locations, self.paths, self.graphs, self.versions = {}, {}, {}, {}
        self.reads, self.cells, self.facts = [], [], []
        self._notes, self._defs_intern = [], {}
        self.initial = self._version(InitialMemory(self.origins[0].id))
        self.alias_queries, self.definition_queries = 0, 0
        self._contexts = {scope.context}
        self.accounting.set('contexts', 1)

    def _origin(self, origin):
        if origin not in self._origin_index:
            raise ValueError('Origin must be registered in the engine')

    def add_object(self, obj, root, cardinality=ObjectCardinality.UNKNOWN,
                   lifetime=ObjectLifetime.UNKNOWN, provenance=('Unknown multiplicity/lifetime',)):
        if obj.id != root.object_id or obj.id.binary != self.scope.function.binary or obj.address_space != root.address_space:
            raise ValueError('Root/object scope or address-space mismatch')
        self._origin(root.origin)
        if obj.id in self.objects:
            if self.objects[obj.id] != obj or self.roots[obj.id] != root:
                raise ValueError('Conflicting object registration')
            return
        self.accounting.check('heap_objects', len(self.objects)+1)
        contexts = self._contexts | ({obj.id.context} if obj.id.context is not None else set())
        self.accounting.check('contexts', len(contexts))
        self.objects[obj.id], self.roots[obj.id] = obj, root
        self.object_facts[obj.id] = HeapObject(obj.id, root.region, cardinality, lifetime, root.origin, tuple(provenance))
        self.accounting.set('heap_objects', len(self.objects))
        self._contexts = contexts
        self.accounting.set('contexts', len(contexts))

    def object_info(self, object_id):
        return self.object_facts[object_id]

    def prove_disjoint(self, a, b, evidence):
        if a == b or a not in self.objects or b not in self.objects or not evidence:
            raise ValueError('Distinct registered objects and storage-disjointness proof required')
        for left, right in ((a, b), (b, a)):
            fact = self.object_facts[left]
            self.object_facts[left] = replace(fact, provenance=fact.provenance + ('p5-disjoint:' + token(right) + ':' + evidence,))

    def _disjoint(self, a, b):
        return any(p.startswith('p5-disjoint:' + token(b) + ':') for p in self.object_facts[a].provenance)

    def path(self, root, segments, width, endian, origin):
        self._origin(origin)
        if root.object_id not in self.objects:
            raise ValueError('Register root before using paths')
        segments = tuple(segments)
        key = token((root, segments, width, endian, origin))
        id_ = AccessPathId(self.scope, 'path-'+key)
        path = AccessPath(id_, root, segments, width, endian, origin, Assessment.complete())
        if id_ not in self.paths:
            self.accounting.check('apg_edges', sum(len(p.segments) for p in self.paths.values())+len(segments))
            self.accounting.check('apg_nodes', len(self.paths)+1)
        self.paths[id_] = path
        return path

    def location(self, root, offset, width, endian, origin, upper=None):
        self._origin(origin)
        if root is not None and root.object_id not in self.objects:
            raise ValueError('Unregistered location object')
        upper = offset if upper is None else upper
        space = root.address_space if root is not None else 'default'
        object_id = root.object_id if root is not None else None
        precise = object_id is not None and offset is not None and offset == upper
        assessment = Assessment.complete() if precise else over('Unknown object or offset range', True)
        if object_id is not None and self.object_facts[object_id].lifetime == ObjectLifetime.FREED:
            assessment = over('Freed-object memory access is incomplete', True)
        key = token((object_id, offset, upper, width, endian, space, origin))
        loc = MemoryLocation(MemoryLocationId(self.scope, 'loc-'+key), object_id, offset, upper,
            width, endian, space, origin, assessment)
        return self._register_location(loc)

    def location_from_path(self, path):
        same_scope(self.scope, path.id)
        if any(isinstance(s, Deref) for s in path.segments):
            return self.location(None, None, path.width_bits, path.endian, path.origin)
        lower = upper = 0
        for segment in path.segments:
            if isinstance(segment, Offset):
                lower += segment.delta_bytes
                upper += segment.delta_bytes
            elif isinstance(segment, Index):
                value = self.dag.constant_value(segment.expression)
                lo, hi = ((value, value) if value is not None else (segment.lower, segment.upper))
                if lo is None: return self.location(self.roots[path.root.object_id], None, path.width_bits, path.endian, path.origin)
                lower += lo*segment.stride_bytes
                upper += hi*segment.stride_bytes
            elif isinstance(segment, UnknownOffset):
                if segment.lower is None: return self.location(path.root, None, path.width_bits, path.endian, path.origin)
                lower += segment.lower
                upper += segment.upper
            else: raise TypeError('Unknown access segment')
        modulus = 1 << self.architecture.pointer_bits
        if lower != upper and (lower//modulus != upper//modulus or upper-lower >= modulus):
            return self.location(path.root, None, path.width_bits, path.endian, path.origin)
        return self.location(path.root, modular_offset(lower, self.architecture.pointer_bits),
            path.width_bits, path.endian, path.origin, modular_offset(upper, self.architecture.pointer_bits))

    def _register_location(self, loc):
        same_scope(self.scope, loc.id)
        self._origin(loc.origin)
        if loc.object_id is not None and loc.object_id not in self.objects:
            raise ValueError('Unknown location object')
        if loc.id in self.locations and self.locations[loc.id] != loc:
            # Endian/width variants must not silently change an existing ID.
            loc = replace(loc, id=MemoryLocationId(self.scope, 'loc-'+token(loc)))
        if loc.id not in self.locations:
            self.accounting.check('heap_cells', len(self.locations)+1)
        self.locations[loc.id] = loc
        return loc

    def _version(self, definition):
        if definition in self._defs_intern:
            return self._defs_intern[definition]
        self.accounting.check('worklist_states', len(self.versions)+1)
        id_ = MemoryVersionId(self.scope, 'mem-'+str(len(self.versions)))
        self.versions[id_] = MemoryVersion(id_, definition)
        self._defs_intern[definition] = id_
        self.accounting.set('worklist_states', len(self.versions))
        return id_

    def resolve_alias(self, state, left, right, budget=QueryBudget()):
        if state not in self.versions: raise ValueError('Unknown memory version')
        same_scope(self.scope, left.id, right.id)
        self.alias_queries += 1
        if left.object_id is None or right.object_id is None:
            return AliasResult(AliasKind.UNKNOWN, (), over('Unknown object may alias', True))
        if left.object_id not in self.objects or right.object_id not in self.objects:
            raise ValueError('Unregistered alias operand')
        if left.address_space != right.address_space:
            # v1 names do not alone establish concrete address-space separation.
            return AliasResult(AliasKind.UNKNOWN, (), over('Address-space relationship unspecified', True))
        if left.object_id != right.object_id:
            if self._disjoint(left.object_id, right.object_id):
                return AliasResult(AliasKind.NO, ('Explicit disjoint-storage proof in object provenance',), Assessment.complete())
            return AliasResult(AliasKind.MAY, (), over('Distinct abstract roots may share concrete storage'))
        fact = self.object_facts[left.object_id]
        if fact.lifetime == ObjectLifetime.FREED:
            return AliasResult(AliasKind.UNKNOWN, (), over('Freed-object access unsupported', True))
        singleton = fact.cardinality == ObjectCardinality.SINGLETON
        a, b = left.byte_interval, right.byte_interval
        modulus = 1 << self.architecture.pointer_bits
        if a and a==b and singleton and 0 <= a[0] < modulus and a[1]-a[0] <= modulus:
            return AliasResult(AliasKind.MUST, ('Same singleton object and exact modular byte access',), Assessment.complete())
        if a and b and max(a[1], b[1]) <= modulus:
            if a[1] <= b[0] or b[1] <= a[0]:
                if singleton:
                    return AliasResult(AliasKind.NO, ('Same singleton object, disjoint byte intervals',), Assessment.complete())
            elif a == b and singleton:
                return AliasResult(AliasKind.MUST, ('Same singleton object and exact byte interval',), Assessment.complete())
        return AliasResult(AliasKind.MAY, (), over('Range overlap or summary-object instance uncertainty'))

    def store(self, parent, location, value, guard=None, origin=None, *,
              alias_constraint=None, unique_constraint=True, coverage_constraint=True):
        if parent not in self.versions: raise ValueError('Unknown parent version')
        location = self._register_location(location)
        origin = origin or location.origin
        self._origin(origin)
        node = self.dag.nodes[value]
        if node.type.kind == TypeKind.BOOL or node.type.bits != location.width_bits:
            raise ValueError('Write value width/type mismatch')
        if guard is not None and self.dag.nodes[guard].type.kind != TypeKind.BOOL:
            raise ValueError('Write guard is not boolean')
        proved = self.resolve_alias(parent, location, location)
        alias = alias_constraint if alias_constraint is not None and alias_constraint.kind != AliasKind.MUST else proved
        unique = proved.kind == AliasKind.MUST and unique_constraint
        coverage = proved.kind == AliasKind.MUST and coverage_constraint
        update = select_update_policy(alias, unique, coverage)
        definition = WriteMemory(parent, location.id, value, guard, update, alias, origin, unique, coverage)
        if definition in self._defs_intern: return self._defs_intern[definition]
        used = sum(self.locations[c.location].width_bits//8 for c in self.cells)
        self.accounting.check('heap_cells', used+location.width_bits//8)
        state = self._version(definition)
        self.cells.append(HeapCell(location.id, value, state, origin, alias.assessment))
        self.accounting.set('heap_cells', used+location.width_bits//8)
        if alias.kind != AliasKind.MUST: self._notes.append(alias.assessment)
        if update == UpdateKind.WEAK: self._notes.append(over('Weak update preserves possible old definitions'))
        return state

    def write(self, request, budget=QueryBudget()):
        if not isinstance(request, WriteMemory): raise TypeError('Typed WriteMemory required')
        state = self.store(request.parent, self.locations[request.location], request.value, request.guard, request.origin,
            alias_constraint=request.alias, unique_constraint=request.unique_target, coverage_constraint=request.exact_coverage)
        # Caller claims cannot elevate a weak operation to a strong update.
        return WriteResult(state, combine((self.versions[state].definition.alias.assessment, *self._notes)))

    def load(self, state, location, guard=None, origin=None):
        if state not in self.versions: raise ValueError('Unknown read version')
        location = self._register_location(location)
        origin = origin or location.origin
        self._origin(origin)
        if guard is not None and self.dag.nodes[guard].type.kind != TypeKind.BOOL:
            raise ValueError('Read guard is not boolean')
        if guard is not None:
            # Guard is carried by ReadMemory in v1. A distinct descriptor ID
            # avoids interning results of different guarded read definitions.
            location = self._register_location(replace(location, id=MemoryLocationId(
                self.scope, 'guarded-loc-'+token((location.id, guard)))))
        # A raw read result is meaningful only on its guard. Conditional clients
        # should use guarded_load with the explicit alternate/previous value.
        ref = self.dag.make(ValueType.bv(location.width_bits), SymbolicOp.MEMORY_READ,
                            origin=origin, state=state, location=location.id)
        read = ReadMemory(state, location.id, ref, guard, origin)
        if read not in self.reads:
            self.accounting.check('worklist_states', len(self.reads)+1)
            self.reads.append(read)
        return ref

    def guarded_load(self, state, location, guard, alternate, origin=None):
        origin = origin or location.origin
        if self.dag.nodes[alternate].type != ValueType.bv(location.width_bits):
            raise ValueError('Guarded read alternate sort mismatch')
        if self.dag.constant_value(guard) is False: return alternate
        result = self.load(state, location, guard, origin)
        return self.dag.operation(SymbolicOp.IF, ValueType.bv(location.width_bits),
                                  (guard, result, alternate), origin)

    def read(self, request, budget=QueryBudget()):
        if not isinstance(request, ReadMemory): raise TypeError('Typed ReadMemory required')
        loc = self.locations[request.location]
        result = self.load(request.state, loc, request.guard, request.origin)
        return ReadResult(result, request.state, combine((loc.assessment, *self._notes)))

    def join(self, inputs, origin):
        self._origin(origin)
        inputs = tuple(inputs)
        if any(i.version not in self.versions for i in inputs): raise ValueError('Unknown join parent')
        for item in inputs:
            if item.guard is not None and self.dag.nodes[item.guard].type.kind != TypeKind.BOOL:
                raise ValueError('Join guard must be boolean')
        self._notes.append(over('Join includes guarded or nondeterministic predecessor choices'))
        return self._version(JoinMemory(inputs, origin))

    def havoc(self, parent, regions, reason, origin, guard=None):
        if parent not in self.versions: raise ValueError('Unknown havoc parent')
        self._origin(origin)
        if guard is not None and self.dag.nodes[guard].type.kind != TypeKind.BOOL: raise ValueError('Havoc guard must be boolean')
        self._notes.append(over('Havoc: '+reason, True))
        return self._version(HavocMemory(parent, tuple(regions), reason, origin, guard))

    def points_to(self, state, address, budget=QueryBudget()):
        if state not in self.versions or address not in self.dag.nodes: raise ValueError('Unknown state/address')
        # Scalar bits alone contain no allocation/provenance proof; conservatively
        # include every registered object and the explicit unknown diagnostic.
        self.accounting.check('alias_candidates', len(self.objects))
        if len(self.objects) > budget.max_alias_candidates:
            raise BudgetExceeded('alias_candidates', budget.max_alias_candidates, len(self.objects))
        self.accounting.counts['alias_candidates'] = max(self.accounting.counts['alias_candidates'], len(self.objects))
        return PointsToResult(tuple(self.objects), over('All known objects plus unenumerated unknown storage', True))

    def resolve(self, reference, budget=QueryBudget()):
        from .memory_version import DefinitionResolver
        resolver = DefinitionResolver(self, budget)
        try:
            return resolver.expression(reference), resolver
        except BudgetExceeded as error:
            self._notes.append(error.assessment)
            raise

    def resolve_definition(self, read, budget=QueryBudget()):
        self.definition_queries += 1
        _, resolver = self.resolve(read.result, budget)
        return DefinitionResult(tuple(v for v in self.versions if v in resolver.definitions), combine(resolver.assessments))

    def constant_value(self, reference):
        resolved, _ = self.resolve(reference)
        return self.dag.constant_value(resolved)

    def possible_constants(self, reference):
        """Finite concrete candidates only, not an exhaustive solver model set.

        Symbolic branches can add arbitrary values. The caller must retain the
        expression/assessment; this helper is for characterization diagnostics.
        """
        from itertools import product
        resolved, _ = self.resolve(reference)
        done, stack = {}, [(resolved, False)]
        while stack:
            ref, ready = stack.pop()
            if ref in done: continue
            n = self.dag.nodes[ref]
            if not ready and n.operands:
                stack.append((ref, True))
                stack.extend((x, False) for x in n.operands if x not in done)
                continue
            value = self.dag.constant_value(ref)
            if value is not None: values = {value}
            elif n.op == SymbolicOp.IF: values = done[n.operands[1]] | done[n.operands[2]]
            elif n.operands:
                values = set()
                for args in product(*(done[x] for x in n.operands)):
                    v = self.dag._calculate(n, args)
                    if v is not None: values.add(v % (1 << n.type.bits) if n.type.kind != TypeKind.BOOL else v)
                    if len(values)>64: raise BudgetExceeded('alias_candidates', 64, len(values))
            else: values = set()
            done[ref] = values
        return tuple(sorted(done[resolved]))

    def add_graph(self, graph):
        same_scope(self.scope, graph.id)
        if graph.id in self.graphs and self.graphs[graph.id]!=graph:
            raise ValueError('Conflicting AccessGraphId cannot replace an existing immutable graph')
        all_graphs = {**self.graphs, graph.id:graph}.values()
        all_graphs = tuple(all_graphs)
        for dim, attr in (('apg_nodes', 'nodes'), ('apg_edges', 'edges'), ('apg_summaries', 'summaries')):
            self.accounting.check(dim, sum(len(getattr(g, attr)) for g in all_graphs))
        self.graphs[graph.id] = graph

    def add_taint(self, fact):
        if fact.memory_version not in self.versions: raise ValueError('Unknown taint state')
        if any(f.id == fact.id and f != fact for f in self.facts): raise ValueError('Conflicting fact ID')
        if fact not in self.facts:
            self.accounting.check('worklist_states', len(self.facts)+1)
            self.facts.append(fact)

    def sink_candidates(self):
        return tuple({'fact':f.id, 'guard':f.guard, 'memory_version':f.memory_version,
            'provenance':f.provenance, 'status':'may', 'confirmed':False} for f in self.facts)

    def snapshot(self, state=None):
        if state is not None and state not in self.versions: raise ValueError('Unknown snapshot state')
        assessments = self._notes + self.accounting.exhaustions + [p.assessment for p in self.paths.values()] + [g.assessment for g in self.graphs.values()]
        assessments += [l.assessment for l in self.locations.values()] + [f.assessment for f in self.facts]
        if any(n.op == SymbolicOp.UNKNOWN for n in self.dag.nodes.values()):
            assessments.append(over('Unsupported symbolic value retained', True))
        return MemorySnapshot(self.scope, self.architecture, self.origins, tuple(self.objects.values()),
            tuple(self.paths.values()), tuple(self.graphs.values()), tuple(self.locations.values()),
            tuple(self.versions.values()), tuple(self.reads), tuple(self.dag.nodes.values()), tuple(self.facts),
            combine(assessments), tuple(self.object_facts.values()), tuple(self.cells), self.budgets)

    @classmethod
    def from_snapshot(cls, snapshot):
        if not isinstance(snapshot, MemorySnapshot): raise TypeError('Validated MemorySnapshot required')
        e = cls(snapshot.scope, snapshot.architecture, snapshot.origin_map, snapshot.budgets)
        e.objects = {o.id:o for o in snapshot.objects}
        e.object_facts = {o.object_id:o for o in snapshot.object_facts}
        from .access_path import AccessRoot
        e.roots = {obj.id:AccessRoot(obj.id, e.object_facts[obj.id].region, obj.address_space,
                   e.object_facts[obj.id].allocation_origin or e.origins[0].id) for obj in snapshot.objects}
        if set(e.objects) != set(e.object_facts): raise ValueError('Runtime import requires multiplicity/lifetime facts')
        e.locations = {x.id:x for x in snapshot.locations}
        e.paths = {x.id:x for x in snapshot.paths}
        e.graphs = {x.id:x for x in snapshot.graphs}
        e.versions = {x.id:x for x in snapshot.versions}
        e._defs_intern = {x.definition:x.id for x in snapshot.versions}
        initials = [x.id for x in snapshot.versions if isinstance(x.definition, InitialMemory)]
        if not initials: raise ValueError('Runtime memory needs an initial definition')
        e.initial = initials[0]
        e.dag.restore(snapshot.expressions)
        e.reads, e.cells, e.facts = list(snapshot.reads), list(snapshot.cells), list(snapshot.taint_facts)
        e._notes = [snapshot.assessment]
        e.accounting.set('heap_objects', len(e.objects))
        e.accounting.set('heap_cells', sum(e.locations[c.location].width_bits//8 for c in e.cells))
        e.accounting.set('worklist_states', len(e.versions))
        e._contexts = {e.scope.context} | {o.id.context for o in snapshot.objects if o.id.context is not None}
        e.accounting.set('contexts', len(e._contexts))
        # Revalidate imported resource collections before exposing a runtime.
        e.accounting.check('heap_cells', len(e.locations))
        e.accounting.check('worklist_states', max(len(e.reads), len(e.facts)))
        e.accounting.check('apg_edges', sum(len(p.segments) for p in e.paths.values()))
        graphs = tuple(e.graphs.values())
        e.graphs={}
        for graph in graphs: e.add_graph(graph)
        return e

    def metrics(self):
        return {**self.accounting.counts, 'dag_unique_nodes':len(self.dag.nodes),
            'apg_nodes':sum(len(g.nodes) for g in self.graphs.values()),
            'apg_edges':sum(len(g.edges) for g in self.graphs.values()),
            'apg_summaries':sum(len(g.summaries) for g in self.graphs.values()),
            'memory_versions':len(self.versions), 'facts':len(self.facts),
            'path_input_segments':sum(len(p.segments) for p in self.paths.values()),
            'alias_queries':self.alias_queries, 'definition_queries':self.definition_queries}


def select_memory_engine(memory_engine='legacy', *, legacy=None, apg=None):
    """Explicit experimental switch, with no fabricated legacy implementation."""
    if memory_engine not in ('legacy', 'apg'): raise ValueError('memory_engine must be legacy|apg')
    selected = legacy if memory_engine == 'legacy' else apg
    if selected is None: raise ValueError('Supply the selected, validated memory-engine instance')
    return selected
