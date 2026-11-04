"""Behavior-preserving P7 binding component."""

from collections import Counter, deque
from dataclasses import replace
import traceback
from typing import Protocol

from emtaint.analysis.dataflow.legacy_demand import (
    ArgumentRead,
    DemandLimit,
)
from emtaint.analysis.framework.summaries import compile_recipe
from emtaint.core import BlockId, MemoryObject, MemoryObjectId
from emtaint.core.contracts import ValueType
from emtaint.ir.canonical import BranchEffect, CallEffect, JumpEffect
from emtaint.memory import AccessRoot, SymbolicOp
from emtaint.memory.abstract_heap import (
    ObjectCardinality,
    ObjectLifetime,
)
from emtaint.memory.policies import BudgetExceeded
from emtaint.memory.state import MemoryLocation
from emtaint.procedures.legacy import (
    ProcedureRule,
    legacy_integer_constraints,
    lookup,
)

from .demand_models import (
    BufferDestination,
    ConstraintRecipe,
    DeferredFormatArgument,
    TaintDependency,
    dependency_order,
)
from .facts import ScalarTaintFact
from .guards import (
    arm_unsigned_hi,
    arm_zero_flag_equal,
    unit_product_arguments,
)
from .subsumption import source_antichain


MAX_RECURSION_DEPTH = 120
MAX_RECIPE_NODES = 256
MAX_DAG_COPY_DEPTH = 12


class BindingOwner(Protocol):
    """Structural owner contract; analysis state remains on the facade."""

    pass


class DemandBinding:
    """Own binding operations while delegating shared state to the facade."""

    def __init__(self, owner: BindingOwner) -> None:
        object.__setattr__(self, "owner", owner)

    def __getattr__(self, name: str) -> object:
        return getattr(self.owner, name)

    def __setattr__(self, name: str, value: object) -> None:
        setattr(self.owner, name, value)

    def _inherit_dependency_metadata(
            self, value, formal, site_guards):
        """Combine caller-bound metadata in the historical field order."""
        constraints=(legacy_integer_constraints(value.constraints)
            if formal.constraint_type==4 else value.constraints)
        return replace(value,
            constraints=self.constraints(constraints, formal.constraints),
            guards=tuple(sorted(set(
                value.guards+formal.guards+site_guards))),
            recipes=tuple(dict.fromkeys(value.recipes+formal.recipes)),
            constraint_type=formal.constraint_type or value.constraint_type,
            unresolved_constraints=(value.unresolved_constraints or
                formal.unresolved_constraints))

    def _bind_deferred_format_argument(
            self, selector, formal, call, block, index, location, scalar):
        """Bind a va_list candidate only when the caller format selects it."""
        candidate=replace(selector.dependency,
            constraints=self.constraints(
                selector.dependency.constraints, formal.constraints),
            guards=tuple(sorted(set(
                selector.dependency.guards+formal.guards))),
            recipes=tuple(dict.fromkeys(
                selector.dependency.recipes+formal.recipes)),
            uncertain=selector.dependency.uncertain or formal.uncertain,
            unresolved_constraints=(
                selector.dependency.unresolved_constraints or
                formal.unresolved_constraints),
            constraint_type=(formal.constraint_type or
                selector.dependency.constraint_type))
        actuals=self.argument(call, selector.format_slot)
        indexes, unresolved=self.format_value_indexes(
            actuals, call.origin, diagnose=False)
        selected=[]
        if selector.position in indexes:
            selected.extend(self.owner.bind_dependencies(
                (candidate,), call, block, index, location, scalar=scalar))
        if not unresolved:
            return selected
        # Keep latent binding from publishing an unselected ordinary Source.
        prior_query=set(self.query_sources)
        prior_partial=set(self.partial_sources)
        try:
            candidates=self.owner.bind_dependencies(
                (candidate,), call, block, index, location, scalar=True)
        finally:
            self.query_sources=prior_query
            self.partial_sources=prior_partial
        format_slots=set()
        for actual in actuals:
            for value in self.owner.scalar_expression(
                    actual, block, index, call.origin):
                if (value.kind in ('argument', 'scalar_argument') and
                        type(value.value) is int):
                    format_slots.add(value.value)
        if not format_slots:
            selected.append(TaintDependency('unknown',
                'Deferred vsnprintf format is not a caller formal at '+
                call.origin, uncertain=True))
        else:
            selected.extend(TaintDependency('format_argument',
                DeferredFormatArgument(slot, selector.position, dependency),
                uncertain=True, unresolved_constraints=True)
                for slot in sorted(format_slots)
                for dependency in candidates)
        return selected

    def _project_bound_source(
            self, dependency, call, site, site_guards):
        """Publish the provisional Source before optional caller refinements."""
        if dependency.kind!='source':
            return None
        provisional=replace(dependency, recipes=(),
            unresolved_constraints=True, uncertain=True,
            guards=tuple(sorted(set(dependency.guards+site_guards))),
            handles=tuple(
                ('unknown', 'Interrupted caller handle binding at '+call.origin)
                if kind=='argument' else (kind, value)
                for kind, value in dependency.handles),
            path=(dependency.path if site in dependency.path
                else dependency.path+(site,)))
        self.owner.observe_sources((provisional,))
        return provisional

    def _bind_one_dependency(
            self, dependency, call, block, index, location, scalar,
            site_guards):
        """Bind one detached dependency and return rows plus a Source row."""
        result=[]
        bound=None
        if dependency.kind=='format_argument':
            result.extend(self._bind_deferred_format_argument(
                dependency.value, dependency, call, block, index, location,
                scalar))
        elif dependency.kind=='hash':
            for root in self.table_state.bind_roots(dependency.value, call):
                result.extend(self.table_state.read(root, call))
        elif dependency.kind=='scalar_argument':
            for value in self.argument(call, dependency.value):
                result.extend(self._inherit_dependency_metadata(
                    item, dependency, site_guards)
                    for item in self.owner.scalar_expression(
                        value, block, index, call.origin))
        elif dependency.kind=='argument':
            for value in self.argument(call, dependency.value):
                if dependency.offset:
                    delta=self.port.constant(
                        dependency.offset %
                        (1<<self.port.engine.architecture.pointer_bits),
                        self.port.type_of(value), call.origin)
                    value=self.port.operation(SymbolicOp.ADD,
                        self.port.type_of(value), (value, delta), call.origin)
                result.extend(self._inherit_dependency_metadata(
                    item, dependency, site_guards)
                    for item in self.buffer(block, index, value, call.origin,
                        whole_region=dependency.offset is None,
                        width_bits=dependency.access_width,
                        byte_access=dependency.byte_access))
        elif dependency.kind=='global':
            value=self.port.constant(dependency.value,
                ValueType.bv(self.port.engine.architecture.pointer_bits),
                call.origin)
            result.extend(self._inherit_dependency_metadata(
                item, dependency, site_guards)
                for item in self.buffer(
                    block, index, value, call.origin))
        else:
            bound=replace(dependency,
                guards=tuple(sorted(set(
                    dependency.guards+site_guards))),
                handles=self.owner.bind_handles(dependency.handles, call))
            if bound.kind=='source':
                if self.active_sink is not None:
                    self.partial_sources.add(bound)
                if not scalar:
                    self.owner.import_source(bound, call, location)
            result.append(bound)
        return result, bound

    def bind_dependencies(self, dependencies, call, block, index,
                          location=None, *, scalar=False):
        """Bind detached callee dependencies into one caller context."""
        result=[]
        site=self.base+call.site.point.instruction_rva
        site_guards=self.owner.path_guards(call)
        ordered=sorted(source_antichain(dependencies,
            lambda narrow, broad:self.covered_sources.add((narrow, broad))),
            key=lambda dep:(dep.kind!='source', dependency_order(dep)))
        for dependency in ordered:
            length_guards=self.owner.guarded_length_guards(
                call, dependency.recipes)
            dependency=replace(dependency,
                guards=tuple(sorted(set(
                    dependency.guards+length_guards))))
            provisional=self._project_bound_source(
                dependency, call, site, site_guards)
            dependency=self.owner.bind_constraints(dependency, call)
            bound_rows, bound=self._bind_one_dependency(
                dependency, call, block, index, location, scalar, site_guards)
            result.extend(bound_rows)
            if provisional is not None:
                self.partial_sources.discard(provisional)
                self.query_sources.discard(provisional)
                self.owner.observe_sources((bound,))
        # Repeated callsites are summarized rather than expanded indefinitely.
        return self.owner.union((tuple(replace(item,
            path=item.path if site in item.path else item.path+(site,),
            uncertain=True,
            guards=tuple(sorted(set(item.guards+site_guards))))
            for item in result),))


    def observe_sources(self, dependencies):
        sources={dependency for dependency in dependencies if dependency.kind=='source'}
        self.query_sources.update(sources)
        if self.active_sink is not None:self.partial_sources.update(sources)

    def union(self, groups):
        def members():
            for group in groups:
                for dependency in group:
                    if dependency.kind=='unknown':
                        # Unknown is the taint-domain upper bound, not a
                        # distinct value for every transitive error string.
                        # Preserve all reasons in the function's evidence
                        # journal while joining the abstract fact itself.
                        self.unknown_evidence.add(str(dependency.value))
                        dependency=replace(dependency, value='Taint correspondence unknown')
                    yield dependency
        # Source paths must reach the antichain callback before dataclass
        # equality collapses them.  Non-Source duplicates (especially joined
        # Unknown reasons) are still removed after that explicit evidence
        # relation has been recorded.
        reduced=source_antichain(members(),
            lambda narrow, broad:self.covered_sources.add((narrow, broad)))
        result=tuple(sorted(dict.fromkeys(reduced), key=dependency_order))
        self.owner.observe_sources(result)
        if len(result)>self.max_dependencies:
            self.alternative_overflows.append({
                'frontier':self.frontier,
                'active_sink':None if self.active_sink is None else self.active_sink.origin,
                'total':len(result),
                'kinds':dict(sorted(Counter(dependency.kind for dependency in result).items())),
                'source_sites':dict(sorted(Counter(str(dependency.value) for dependency in result
                    if dependency.kind=='source').items(), key=lambda item:(-item[1], item[0]))[:16]),
                'source_guard_counts':dict(sorted(Counter(len(dependency.guards) for dependency in result
                    if dependency.kind=='source').items())),
                'source_recipe_counts':dict(sorted(Counter(len(dependency.recipes) for dependency in result
                    if dependency.kind=='source').items())),
                'source_path_counts':dict(sorted(Counter(len(dependency.path) for dependency in result
                    if dependency.kind=='source').items())),
                'query_sources_after_observe':len(self.query_sources),
                'partial_sources_after_observe':len(self.partial_sources),
                'stack':tuple(frame.name+':'+str(frame.lineno) for frame in traceback.extract_stack(limit=8)[:-1]),
            })
            raise DemandLimit(
                'Taint dependency alternatives budget; no empty-flow '
                'conclusion', dimension='alternatives')
        return result

    def path_guards(self, call):
        """Retain recognized guards on every resolved CIR path to a call.

        A unique unconditional jump can remove an imported speculative edge.
        An incomplete CFG still makes these observations conditional evidence,
        never an UNSAT result or a clean-source proof.
        """
        if call.origin in self.path_guard_cache:return self.path_guard_cache[call.origin]
        cfg=self.cfg
        destination=call.site.point.block
        if cfg.entry is None or destination not in cfg.nodes:return ()
        by_block={block.id:block for block in self.function.blocks}
        candidates=[]
        for block in self.function.blocks:
            for branch in (effect for effect in block.effects if isinstance(effect, BranchEffect)):
                pattern=(arm_zero_flag_equal(
                    block.effects, branch.condition) or
                    arm_unsigned_hi(block.effects, branch.condition))
                if pattern is not None:candidates.append((block.id, branch, pattern))
        if not candidates:
            self.path_guard_cache[call.origin]=()
            self.path_guard_operands[call.origin]=()
            return ()
        edges=set(cfg.edges)
        for source, block in by_block.items():
            outgoing={edge for edge in edges if edge.source==source}
            if len(outgoing)<2 or any(isinstance(effect, BranchEffect) for effect in block.effects):continue
            jumps=[effect for effect in block.effects if isinstance(effect, JumpEffect)]
            if len(jumps)!=1:continue
            target=jumps[0].target
            if isinstance(target, BlockId):addresses={target.rva}
            else:
                try:values=self.demand.value(target)
                except DemandLimit:continue
                addresses={value-self.base for ref in values
                    if type(value:=self.demand.guard_concrete(ref)) is int}
            if len(addresses)==1:
                edges.difference_update(edge for edge in outgoing if edge.target.rva not in addresses)

        adjacency={node:[] for node in cfg.nodes}
        for edge in edges:adjacency.setdefault(edge.source, []).append(edge)

        def dominates(edge):
            seen={cfg.entry}
            todo=deque((cfg.entry,))
            while todo:
                current=todo.popleft()
                for candidate in adjacency.get(current, ()):
                    if candidate==edge or candidate.target in seen:continue
                    seen.add(candidate.target)
                    todo.append(candidate.target)
            return destination not in seen

        observations=[]
        for source, branch, pattern in candidates:
            for polarity, target in ((True, branch.if_true), (False, branch.if_false)):
                edge=next((edge for edge in adjacency.get(source, ()) if edge.target==target), None)
                if edge is None or not dominates(edge):continue
                try:values=self.demand.value(pattern.right)
                except DemandLimit:continue
                bounds={number for ref in values
                    if type(number:=self.demand.guard_concrete(ref)) is int}
                if len(bounds)!=1:continue
                observations.append((branch.origin, pattern.relation(polarity)+str(pattern.bits),
                    next(iter(bounds)), pattern.left))
        answer=tuple(sorted({row[:3] for row in observations}))
        self.path_guard_cache[call.origin]=answer
        self.path_guard_operands[call.origin]=tuple(observations)
        return answer

    def guarded_length_guards(self, call, recipes: tuple) -> tuple:
        """Relate a portable length recipe to exact SSE operands on this path.

        The result is a conditional guard annotation. It never replaces the
        residual recipe or makes an incomplete CFG a proof of safety.
        """
        key=call.origin, tuple(recipe.key for recipe in recipes)
        if key in self.guarded_length_cache:
            return self.guarded_length_cache[key]
        self.owner.path_guards(call)
        observations=self.path_guard_operands.get(call.origin, ())
        equal=[row for row in observations if row[1]=='eq32' and row[2]==1]
        upper=[row for row in observations if row[1]=='ule32' and 0<=row[2]<0xffffffff]

        def symbolic_root(reference):
            for _ in range(MAX_DAG_COPY_DEPTH):
                node=self.port.engine.dag.nodes[reference]
                if node.op!=SymbolicOp.COPY:
                    return reference if node.op in (SymbolicOp.SYMBOL, SymbolicOp.MEMORY_READ) else None
                reference=node.operands[0]
            return None

        def exact_operand(reference):
            try:values=self.demand.value(reference)
            except DemandLimit:return None
            roots={symbolic_root(value) for value in values}
            if len(roots)!=1 or None in roots:
                return None
            root=next(iter(roots))
            return root if self.port.engine.dag.nodes[root].type.bits==32 else None

        answer=set()
        if equal and upper:
            for recipe in recipes:
                slots=unit_product_arguments(recipe.value)
                if slots is None:continue
                operands={slot:exact_operand(call.arguments[slot]) for slot in slots if slot<len(call.arguments)}
                if len(operands)!=2 or None in operands.values():continue
                for unit in equal:
                    unit_root=exact_operand(unit[3])
                    if unit_root is None:continue
                    for bound in upper:
                        bound_root=exact_operand(bound[3])
                        if bound_root is None:continue
                        if any(operands[first]==unit_root and operands[second]==bound_root
                               for first, second in (slots, slots[::-1])):
                            answer.add((call.origin, 'length-ule32', bound[2]))
        result=tuple(sorted(answer))
        self.guarded_length_cache[key]=result
        return result

    def length_recipes(self, call, rule):
        key=call.origin, rule
        if key not in self.recipe_cache:self.recipe_cache[key]=self._length_recipes(call, rule)
        return self.recipe_cache[key]

    def _length_recipes(self, call, rule):
        if not rule.lengths or self.constants(call, rule.lengths):return ()
        values=(self.port.constant(1, ValueType.bv(self.port.engine.architecture.pointer_bits), call.origin),)
        for slot in rule.lengths:
            values=self.demand.union((self.port.operation(SymbolicOp.MUL, self.port.type_of(a), (a, b), call.origin),)
                for a in values for b in self.argument(call, slot))
        recipe=compile_recipe(self.demand, values, provenance=('Legacy source/copy length Cons use-def substitution',))
        if len(recipe.nodes)>MAX_RECIPE_NODES:
            self.unresolved_recipe_calls.add(call.origin)
            self.pending.append((call.origin, 'Length recipe exceeds 256 nodes; bound unknown, known source retained'))
            return ()
        return (ConstraintRecipe.wrap(recipe),)

    def bind_constraints(self, dependency, call):
        numbers=[]
        pending=[]
        unresolved_constraints=dependency.unresolved_constraints
        for recipe in dependency.recipes:
            self.port.validate_current()
            key=recipe.key, call.origin
            if key in self.bound_recipe_cache:
                concrete, residual, budgeted=self.bound_recipe_cache[key]
                numbers.extend(concrete)
                pending.extend(residual)
                unresolved_constraints |= budgeted
                continue
            try:values=recipe.value.instantiate(self.demand, call)
            except DemandLimit as error:
                self.local_failure(error, call.origin)
                values=(self.port.unknown(ValueType.bv(self.port.engine.architecture.pointer_bits), call.origin,
                    'Unresolved inherited length constraint: '+str(error)),)
            unresolved=[]
            concrete=[]
            residuals=[]
            budgeted=False
            for value in values:
                number=self.demand.guard_concrete(value)
                if type(number) is int:concrete.append(number)
                else:unresolved.append(value)
            if unresolved:
                residual=compile_recipe(self.demand, unresolved, provenance=recipe.value.provenance)
                if len(residual.nodes)>MAX_RECIPE_NODES:
                    budgeted=True
                    self.pending.append((call.origin,
                        'Residual length recipe budget; bound remains unknown '
                        'and source propagation continues'))
                else:residuals.append(ConstraintRecipe.wrap(residual))
            self.bound_recipe_cache[key]=tuple(concrete), tuple(residuals), budgeted
            unresolved_constraints |= budgeted
            numbers.extend(concrete)
            pending.extend(residuals)
        return replace(
            dependency,
            constraints=self.constraints(dependency.constraints, numbers),
            recipes=tuple(dict.fromkeys(pending)),
            unresolved_constraints=unresolved_constraints,
        )

    def register_source_fact(self, call:CallEffect, location:MemoryLocation, rule:ProcedureRule)->None:
        """Record the old callsite Source without demanding its later uses."""
        p=self.port
        e=p.engine
        site=self.base+call.site.point.instruction_rva
        if location.object_id is None:
            if call.origin not in self.unknown_roots:
                obj=MemoryObjectId.unknown(
                    p.scope.function.binary,
                    'source-buffer',
                    'Unknown source destination',
                    call.origin,
                    p.scope.context,
                )
                root=AccessRoot(obj, 'unknown', 'default', call.origin)
                e.add_object(
                    MemoryObject(obj, 'Unresolved source destination'),
                    root,
                    ObjectCardinality.UNKNOWN,
                    ObjectLifetime.UNKNOWN,
                    ('Actual source call has an unresolved destination; '
                     'no NoAlias claim',),
                )
                self.unknown_roots[call.origin]=root
            location=e.location(self.unknown_roots[call.origin], None, 8, e.architecture.endian, call.origin)
        key=call.origin, location.object_id, location.offset_lower
        lengths=self.constants(call, rule.lengths)
        if key not in self.source_bindings:
            value=p.symbol('taint-source-byte:'+call.origin, ValueType.bv(8), call.origin)
            gs=self.demand.value(call.guard)
            guard=gs[0] if len(gs)==1 else p.unknown(ValueType.boolean(), call.origin, 'Source guard alternatives')
            state=p.write(self.demand.initial.memory, location, value, guard, call.origin).state
            provenance=(
                rule.provenance,
                'Actual CIR source call; buffer extent and feasibility '
                'remain may',
            )+tuple(
                'Known-CIR path guard, CFG completeness unproved: '+repr(item)
                for item in self.owner.path_guards(call)
            )
            self.source_bindings[key]=self.regions.bind(
                state, location, site, call.origin, guard=guard,
                constraints=lengths, provenance=provenance)

    def register_scalar_source_fact(self, call:CallEffect)->ScalarTaintFact|None:
        """Keep the old return Source on its actual CIR ValueRef, without an AST copy."""
        if not call.results:return None
        value_id=call.results[0].id
        if value_id not in self.scalar_source_facts:
            guards=self.demand.value(call.guard)
            guard=guards[0] if len(guards)==1 else None
            uncertain=guard is None or self.demand.guard_concrete(guard) is not True
            self.scalar_source_facts[value_id]=ScalarTaintFact(value_id,
                call.site.point, self.port.scope.context, guard,
                self.base+call.site.point.instruction_rva, call.origin, uncertain)
        return self.scalar_source_facts[value_id]

    def source(self, call, location, rule):
        site=self.base+call.site.point.instruction_rva
        if rule.operation=='source_return':self.owner.register_scalar_source_fact(call)
        self.owner.register_source_fact(call, location, rule)
        lengths=self.constants(call, rule.lengths)
        provisional=TaintDependency(
            'source', site, lengths, (site,), True,
            handles=((
                'unknown',
                'Source handle/length binding incomplete at '+call.origin,
            ),),
            unresolved_constraints=True,
        )
        self.owner.observe_sources((provisional,))
        handles=(self.union_handles(
            self.owner.handle(value)
            for value in self.argument(call, rule.source)
        ) if (rule.operation=='source_buffer' and rule.source is not None)
            else ())
        recipes=self.owner.length_recipes(call, rule)
        guards=tuple(sorted(set(self.owner.path_guards(call)+self.owner.guarded_length_guards(call, recipes))))
        dependency=TaintDependency(
            'source', site, lengths, (site,), True,
            guards=guards,
            handles=handles,
            recipes=recipes,
            unresolved_constraints=call.origin in self.unresolved_recipe_calls,
        )
        self.partial_sources.discard(provisional)
        self.query_sources.discard(provisional)
        self.owner.observe_sources((dependency,))
        return dependency

    def handle(self, reference, seen=frozenset()):
        """Backward Udata handle lineage, including fdopen/socket override."""
        self.tick()
        d=self.demand
        e=self.port.engine
        if reference in seen:return (('unknown', 'recursive-handle'),)
        node=e.dag.nodes[reference]
        seen=seen|{reference}
        if node.op==SymbolicOp.SYMBOL:
            if node.value.startswith('argument:'):return (('argument', int(node.value.split(':')[1])),)
            call=d.return_calls.get(node.value)
            if call is not None:
                rule=lookup(d.call_name(call))
                site=self.base+call.site.point.instruction_rva
                if rule and rule.operation=='socket_handle':return (('socket', site),)
                if rule and rule.returns_file_handle:
                    inputs=(self.union_handles(self.owner.handle(v, seen) for v in self.argument(call, rule.source))
                        if rule.operation=='file_handle' and rule.source is not None else ())
                    return self.union_handles(((('file', site),), inputs))
                values=[]
                for callee in self.call_functions(call):
                    summary=self.summaries.get(callee)
                    if summary:
                        for dep in summary.returns:
                            if dep.kind=='handle':values.append((dep.value,))
                            elif dep.kind=='argument':
                                values.extend(
                                    self.owner.handle(value, seen)
                                    for value in self.argument(
                                        call, dep.value))
                if values:return self.union_handles(values)
        if reference in d.loads:
            # Handle loads still require memory use/def correspondence. Unknown
            # cannot be relabeled as a file source simply because fread uses it.
            return (('unknown', d.loads[reference][3]),)
        if node.op in (SymbolicOp.ADD, SymbolicOp.SUB) and len(node.operands)==2:
            left, right=node.operands
            if node.op==SymbolicOp.ADD and e.dag.nodes[left].op==SymbolicOp.CONSTANT and e.dag.nodes[left].value==0:
                return self.owner.handle(right, seen)
            if e.dag.nodes[right].op==SymbolicOp.CONSTANT and e.dag.nodes[right].value==0:
                return self.owner.handle(left, seen)
        if node.operands:return self.union_handles(self.owner.handle(v, seen) for v in node.operands)
        return (('unknown', node.origin),)

    def bind_handles(self, handles, call):
        return self.union_handles(self.union_handles(self.owner.handle(v) for v in self.argument(call, value))
            if kind=='argument' else ((kind, value),) for kind, value in handles)

    def import_source(self, dependency, call, location=None):
        """Project a detached callee may-source into this caller's memory scope."""
        p=self.port
        e=p.engine
        if location is None or location.object_id is None:
            key='summary-source:'+call.origin
            if key not in self.unknown_roots:
                obj=MemoryObjectId.unknown(
                    p.scope.function.binary,
                    'summary-source',
                    'Unresolved callee source pointee',
                    key,
                    p.scope.context,
                )
                root=AccessRoot(obj, 'unknown', 'default', call.origin)
                e.add_object(
                    MemoryObject(obj, 'Callee source projection'),
                    root,
                    ObjectCardinality.UNKNOWN,
                    ObjectLifetime.UNKNOWN,
                    ('Portable callee source; caller correspondence is may, '
                     'not exact',),
                )
                self.unknown_roots[key]=root
            location=e.location(self.unknown_roots[key], None, 8, e.architecture.endian, call.origin)
        if location.width_bits!=8:
            root=e.roots[location.object_id]
            upper=None if location.offset_upper is None else location.offset_upper+location.width_bits//8-1
            location=e.location(root, location.offset_lower, 8, e.architecture.endian, call.origin, upper=upper)
        key=call.origin, dependency.value, location.object_id, location.offset_lower, location.offset_upper
        if key in self.imported_bindings:return
        guards=self.demand.value(call.guard)
        guard=(guards[0] if len(guards)==1 else p.unknown(
            ValueType.boolean(), call.origin,
            'Callee call guard alternatives'))
        value=p.symbol('summary-source-byte:'+str(dependency.value), ValueType.bv(8), call.origin)
        state=p.write(self.demand.initial.memory, location, value, guard, call.origin).state
        self.imported_bindings[key]=self.regions.bind(state, location, dependency.value, call.origin, guard=guard,
            constraints=dependency.constraints,
            provenance=(
                'Actual callee summary projected at caller CIR call',
                'Inherited source guards: '+repr(dependency.guards),
                'Representative source path: '+repr(dependency.path),
            ),
        )

    def expression(self, reference, block, index, origin):
        key=reference, block, index
        if key in self.expression_cache:return self.expression_cache[key]
        if key in self.expression_active:
            return (TaintDependency(
                'unknown', 'Recursive value requirement', uncertain=True),)
        if len(self.expression_active)>=MAX_RECURSION_DEPTH:
            return (self.local_failure(DemandLimit('Taint expression demand depth budget', dimension='depth'), origin),)
        self.expression_active.add(key)
        try:
            result=self._expression(reference, block, index, origin)
            self.expression_cache[key]=result
            return result
        finally:self.expression_active.remove(key)

    def scalar_expression(self, reference, block, index, origin):
        """Value taint, keeping formal scalar inputs apart from pointees."""
        self.tick()
        key=reference, block, index
        if key in self.scalar_cache:return self.scalar_cache[key]
        if (key in self.scalar_active or
                len(self.scalar_active)>=MAX_RECURSION_DEPTH):
            return (TaintDependency('unknown', 'Unresolved scalar value recursion', uncertain=True),)
        self.scalar_active.add(key)
        d=self.demand
        node=self.port.engine.dag.nodes[reference]
        try:
            if node.op==SymbolicOp.SYMBOL and node.value.startswith('argument:'):
                result=(TaintDependency('scalar_argument', int(node.value.split(':')[1])),)
            elif node.op==SymbolicOp.SYMBOL and node.value in d.return_calls:
                call=d.return_calls[node.value]
                source_block, source_index, _=self.calls[call.origin]
                if all(d.guard_concrete(value) is False for value in d.value(call.guard)):
                    result=(TaintDependency(
                        'unknown',
                        'Nonexecuted call has no defined scalar result',
                        uncertain=True,
                    ),)
                elif lookup(d.call_name(call)) is not None:
                    result=self.owner.expression(
                        reference, block, index, origin)
                else:
                    groups=[]
                    callees=self.call_functions(call)
                    for callee in callees:
                        summary=self.summaries.get(callee)
                        if summary is None or summary.scalar_returns is None:
                            groups.append((TaintDependency(
                                'unknown',
                                'Callee scalar return mode unavailable: '+
                                hex(callee),
                                uncertain=True,
                            ),))
                        else:
                            groups.append(self.owner.bind_dependencies(
                                summary.scalar_returns, call, source_block,
                                source_index, scalar=True))
                            if summary.pending:
                                groups.append((TaintDependency(
                                    'unknown',
                                    'Incomplete callee scalar return',
                                    uncertain=True,
                                ),))
                    if not callees:
                        groups.append((TaintDependency(
                            'unknown', 'Unresolved scalar return target',
                            uncertain=True),))
                    result=self.owner.union(groups)
            elif reference in d.loads:
                result=self.owner.expression(
                    reference, block, index, origin)
            elif node.op in (SymbolicOp.UNKNOWN, SymbolicOp.SYMBOL, SymbolicOp.MEMORY_READ):
                result=(TaintDependency(
                    'unknown',
                    'Unresolved scalar value: '+str(node.value or node.origin),
                    uncertain=True,
                ),)
            else:
                result=(self.owner.union(self.owner.scalar_expression(
                    child, block, index, origin)
                    for child in node.operands) if node.operands else ())
            self.scalar_cache[key]=result
            return result
        finally:self.scalar_active.remove(key)

    def length_taint(self, call, rule, block, index):
        return self.owner.union(self.owner.scalar_expression(
            value, block, index, call.origin)
            for slot in rule.lengths for value in self.argument(call, slot))

    def in_length_channel(self, operation):
        """Length-only Sources must never become buffer Sources on a limit."""
        saved=self.partial_sources, self.query_sources
        self.partial_sources=set()
        self.query_sources=set()
        try:return operation()
        except (DemandLimit, BudgetExceeded, RecursionError):
            if self.active_sink is not None:
                unknown=TaintDependency('unknown', 'Length-taint query incomplete', uncertain=True)
                sources=tuple(sorted(
                    self.partial_sources|self.query_sources,
                    key=dependency_order,
                ))
                self.active_sink=replace(
                    self.active_sink,
                    length_dependencies=sources+(unknown,),
                )
            raise
        finally:self.partial_sources, self.query_sources=saved

    def bind_sink(self, sink, call, block, index):
        offsets=set(sink.offsets)
        destinations=[]
        p=self.port
        for destination in sink.destinations:
            if destination.kind!='argument':
                destinations.append(destination)
                continue
            if destination.offset is None:
                destinations.append(BufferDestination(
                    'unknown',
                    'Unknown destination displacement at '+call.origin,
                    None,
                ))
                continue
            for value in self.argument(call, destination.value):
                if destination.offset:
                    delta=p.constant(
                        destination.offset %
                        (1<<p.engine.architecture.pointer_bits),
                        p.type_of(value),
                        call.origin,
                    )
                    value=p.operation(SymbolicOp.ADD, p.type_of(value), (value, delta), call.origin)
                sizes, pending=self.destination(value, call.origin)
                offsets.update(sizes)
                destinations.extend(pending)
        bound=replace(sink, offsets=tuple(sorted(offsets)), destinations=tuple(sorted(set(destinations), key=repr)))
        if sink.length_dependencies:
            bound=replace(bound, length_dependencies=(TaintDependency(
                'unknown', 'Caller length-taint binding pending',
                uncertain=True),))
        self.active_sink=bound
        try:
            buffers=self.owner.bind_dependencies(
                sink.dependencies, call, block, index)
        except DemandLimit as error:
            if error.dimension not in ('alternatives', 'depth'):raise
            self.pending.append((call.origin, 'Inherited buffer binding incomplete: '+str(error)))
            buffers=(tuple(sorted(self.partial_sources|self.query_sources, key=dependency_order))+
                (TaintDependency('unknown', 'Inherited buffer alternatives incomplete', uncertain=True),))
        self.active_sink=replace(bound, dependencies=buffers)
        if sink.length_dependencies:
            try:
                lengths=self.owner.in_length_channel(
                    lambda:self.owner.bind_dependencies(
                        sink.length_dependencies, call, block, index,
                        scalar=True))
            except DemandLimit as error:
                if error.dimension not in ('alternatives', 'depth'):raise
                self.pending.append((call.origin, 'Inherited length binding incomplete: '+str(error)))
                lengths=self.active_sink.length_dependencies
            self.active_sink=replace(self.active_sink, length_dependencies=lengths)
        return self.active_sink

    def _expression(self, reference, block, index, origin):
        self.tick()
        p=self.port
        d=self.demand
        e=p.engine
        node=e.dag.nodes[reference]
        if node.op==SymbolicOp.SYMBOL:
            if node.value.startswith('argument:'):return (TaintDependency('argument', int(node.value.split(':')[1])),)
            if node.value in d.return_calls:
                call=d.return_calls[node.value]
                source_block, source_index, _=self.calls[call.origin]
                rule=lookup(d.call_name(call))
                if rule and rule.operation=='source_return':
                    location=e.location(
                        None, None, 8, e.architecture.endian, call.origin)
                    return (self.owner.source(call, location, rule),)
                if rule and rule.operation=='deref_return':
                    return self.owner.union(self.buffer(
                        source_block, source_index, pointer, call.origin)
                        for address in self.argument(call, rule.source)
                        for pointer in d.read(
                            source_block, source_index, address,
                            ArgumentRead(
                                e.architecture.pointer_bits,
                                e.architecture.endian,
                                call.origin,
                            ),
                            0,
                        ))
                if rule and rule.operation in ('file_handle', 'socket_handle'):
                    return tuple(TaintDependency('handle', handle) for handle in self.owner.handle(reference))
                if rule and rule.operation in ('return_alias', 'stateful_token', 'integer_return'):
                    if rule.operation=='stateful_token':return self.token_dependencies(call, source_block, source_index)
                    dependencies=self.owner.union(self.buffer(
                        source_block, source_index, value, call.origin)
                        for value in self.argument(call, rule.source))
                    if rule.operation=='integer_return':
                        return tuple(replace(
                            dependency,
                            constraints=legacy_integer_constraints(
                                dependency.constraints)
                                if rule.constraint_type==4
                                else dependency.constraints,
                            constraint_type=rule.constraint_type,
                        ) for dependency in dependencies)
                    return dependencies
                callees=self.call_functions(call)
                result=self.owner.union(self.owner.bind_dependencies(
                    self.summaries[f].returns, call, source_block, source_index)
                    for f in callees if f in self.summaries)
                return result or (TaintDependency(
                    'unknown',
                    'Unresolved callee return taint at '+call.origin,
                    uncertain=True,
                ),)
        if reference in d.loads:
            position=self.load_positions.get(
                d.loads[reference][3], (block, index))
            return self.buffer(
                *position, d.loads[reference][0], origin,
                width_bits=d.loads[reference][1], byte_access=True)
        if node.op in (SymbolicOp.UNKNOWN, SymbolicOp.SYMBOL, SymbolicOp.MEMORY_READ):
            return (TaintDependency(
                'unknown',
                'Unresolved value taint: '+str(node.value or node.origin),
                uncertain=True,
            ),)
        if not node.operands:
            return ()
        return self.owner.union(self.owner.expression(
            child, block, index, origin) for child in node.operands)
