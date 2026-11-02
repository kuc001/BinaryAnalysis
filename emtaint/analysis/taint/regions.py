"""P7 may-taint on versioned regions, complementing value/byte dependencies.

The old source/copy rules taint buffers, including unresolved extents. These
facts must survive a may-write/havoc without pretending that memory is clean.
All address comparisons go through MemoryQueryPort; strong clean definitions
kill only exactly covered singleton bytes on an unconditional path.
"""
from dataclasses import dataclass
from emtaint.core.contracts import ValueType
from emtaint.memory import (TaintFact, WriteMemory, JoinMemory, HavocMemory,
    AliasKind, UpdateKind, Offset, Deref, UnknownOffset)
from emtaint.memory.engine import token, over
from emtaint.memory.access_graph import AccessGraphArena
from emtaint.memory.abstract_heap import ObjectCardinality
from emtaint.memory.policies import BudgetExceeded


@dataclass(frozen=True)
class RegionBinding:
    fact:object
    location:object
    source_site:object
    constraints:tuple=()


@dataclass(frozen=True)
class RegionFlow:
    binding:RegionBinding
    memory:object
    sink_origin:str
    guards:tuple
    alias_kind:object
    incomplete:bool
    confirmed:bool=False


class RegionTaintTracker:
    def __init__(self, port, *, max_steps=100000):
        self.port=port
        self.seeds={}
        self.max_steps=max_steps
        self.steps=0
        self.apg=port.apg

    def bind(self, state, location, source_site, origin, *, guard=None, constraints=(), provenance=(), access_root=None, segments=None):
        p=self.port
        e=p.engine
        p.validate_current()
        if location.object_id is None:raise ValueError('A source region needs a stable root; unknown address must be diagnosed')
        root=e.roots[location.object_id] if access_root is None else access_root
        segment=(Offset(location.offset_lower) if location.offset_lower==location.offset_upper and location.offset_lower is not None else
                 UnknownOffset(location.offset_lower, location.offset_upper, 'Unresolved source/copy extent'))
        path=e.path(root, (segment, Deref(e.architecture.pointer_bits, location.width_bits, location.endian)) if segments is None else segments,
            location.width_bits, location.endian, origin)
        graph=self.apg.intern(path, p.point(origin))
        e.add_graph(graph)
        fact_provenance=tuple(provenance)+('Original source/copy buffer rule; versioned region may-flow',)
        assessment=over('Buffer/alias abstraction requires path and solver validation', True)
        # The ID must distinguish every field that participates in TaintFact
        # equality. Table projections can share state/location/APG/source but
        # carry different inherited guard/path provenance; omitting it creates
        # the same ID for unequal facts on a later fixed-point round.
        identity=(state, location.id, source_site, guard, tuple(constraints), root, graph.id,
            p.scope.context, 'may-buffer', origin, fact_provenance, assessment)
        fact=TaintFact('region-'+token(identity), root, None, graph.id, p.scope.context,
            state, guard, 'may-buffer', origin, fact_provenance, assessment)
        e.add_taint(fact)
        binding=RegionBinding(fact, location, source_site, tuple(constraints))
        existing=self.seeds.setdefault(state, [])
        if binding not in existing:existing.append(binding)
        return binding

    def query(self, state, location, origin, guards=()):
        p=self.port
        e=p.engine
        p.validate_current()
        todo=[(state, tuple(guards), False)]
        seen=set()
        flows={}
        steps=0
        while todo:
            current, conditions, incomplete=todo.pop()
            identity=current, conditions, incomplete
            if identity in seen:continue
            seen.add(identity)
            steps+=1
            self.steps+=1
            if steps>self.max_steps:raise BudgetExceeded('worklist_iterations', self.max_steps, steps)
            if any(p.concrete(g) is False for g in conditions):continue
            for binding in self.seeds.get(current, ()):
                alias=p.alias(state, binding.location, location)
                if alias.kind==AliasKind.NO:continue
                gs=conditions+(() if binding.fact.guard is None else (binding.fact.guard,))
                if any(p.concrete(g) is False for g in gs):continue
                flow=RegionFlow(binding, state, origin, tuple(dict.fromkeys(gs)), alias.kind,
                    incomplete or alias.kind!=AliasKind.MUST)
                flows[binding.fact.id, flow.guards, flow.incomplete]=flow
            definition=e.versions[current].definition
            if isinstance(definition, WriteMemory):
                guard=definition.guard
                if guard is not None and p.concrete(guard) is False:
                    todo.append((definition.parent, conditions, incomplete))
                    continue
                write=e.locations[definition.location]
                alias=p.alias(state, write, location)
                a, b=write.byte_interval, location.byte_interval
                exact=(write.object_id==location.object_id and write.object_id is not None and a is not None and b is not None
                    and a[0]<=b[0] and b[1]<=a[1] and e.object_facts[write.object_id].cardinality==ObjectCardinality.SINGLETON
                    and definition.update==UpdateKind.STRONG)
                if alias.kind!=AliasKind.NO and exact:
                    if guard is None or p.concrete(guard) is True:continue
                    neg=p.operation('not', ValueType.boolean(), (guard,), origin)
                    todo.append((definition.parent, conditions+(neg,), incomplete))
                else:todo.append((definition.parent, conditions, incomplete or alias.kind not in (AliasKind.NO, AliasKind.MUST)))
            elif isinstance(definition, JoinMemory):
                todo.extend((edge.version, conditions+(() if edge.guard is None else (edge.guard,)), incomplete) for edge in definition.inputs)
            elif isinstance(definition, HavocMemory):
                # A possible write cannot prove the previous source absent.
                # Keep it as incomplete may-flow, with the current version.
                todo.append((definition.parent, conditions, True))
        return tuple(flows.values())
