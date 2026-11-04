"""Behavior-preserving P7 memory component."""


from collections import deque
from dataclasses import dataclass, replace
from typing import Protocol

from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.ir.canonical import (
    BranchEffect,
    CallEffect,
    StoreEffect,
    UnknownEffect,
)
from emtaint.memory import AliasKind, SymbolicOp
from emtaint.memory.abstract_heap import ObjectCardinality
from emtaint.procedures.legacy import (
    lookup,
    uniform_copy_length_constraints,
)

from .demand_models import BufferDestination, TaintDependency
from .global_outputs import location as global_output_location
from .guards import legacy_constraint


@dataclass(frozen=True)
class BufferFrontier:
    """One immutable reverse-CFG frontier for a buffer demand."""

    block: object
    cutoff: int
    constraints: tuple
    guards: tuple


class MemoryOwner(Protocol):
    """Structural owner contract; analysis state remains on the facade."""

    pass


class DemandMemory:
    """Own memory operations while delegating shared state to the facade."""

    def __init__(self, owner: MemoryOwner) -> None:
        object.__setattr__(self, "owner", owner)

    def __getattr__(self, name: str) -> object:
        return getattr(self.owner, name)

    def __setattr__(self, name: str, value: object) -> None:
        setattr(self.owner, name, value)

    def _normalize_buffer_location(
            self, reference, origin, whole_region, width_bits):
        """Normalize one buffer reference without changing alias precision."""
        engine=self.port.engine
        location=self.location(reference, origin)
        if width_bits!=8:
            root=(engine.roots[location.object_id]
                if location.object_id is not None else None)
            location=engine.location(root, location.offset_lower, width_bits,
                engine.architecture.endian, origin,
                upper=location.offset_upper)
        if whole_region and location.object_id is not None:
            location=engine.location(engine.roots[location.object_id], None,
                8, engine.architecture.endian, origin)
        return location

    def _scan_store_effect(
            self, effect, location, current, position, byte_access, result):
        """Apply one Store definition and return its historical kill result."""
        if getattr(effect.guard, 'value', None) is False:
            return False
        demand=self.demand
        engine=self.port.engine
        binding=demand.local_address(effect.address)
        written=(engine.location(*binding, effect.width_bits, effect.endian,
            effect.origin) if binding else engine.location(
                None, None, effect.width_bits, effect.endian, effect.origin))
        alias=self.port.alias(demand.initial.memory, written, location)
        if alias.kind==AliasKind.NO:
            return False
        corresponding=(written.object_id is not None and
            written.object_id==location.object_id)
        if not corresponding:
            result.append(TaintDependency('unknown',
                'Unproved store correspondence at '+effect.origin,
                uncertain=True))
            return False
        try:
            values=demand.value(effect.value)
        except DemandLimit as error:
            result.append(self.local_failure(error, effect.origin))
            return False
        for value in values:
            result.extend(self.expression(
                value, current, position, effect.origin))
        # Preserve the definition write after value expansion.
        for value in values:
            self.port.write(demand.initial.memory, written, value,
                demand.value(effect.guard)[0], effect.origin)
        written_interval=written.byte_interval
        location_interval=location.byte_interval
        covered=(written.object_id==location.object_id and
            written.object_id is not None and
            written_interval is not None and location_interval is not None and
            written_interval[0]<=location_interval[0] and
            location_interval[1]<=written_interval[1] and
            engine.object_facts[written.object_id].cardinality==
            ObjectCardinality.SINGLETON)
        return (byte_access and covered and
            getattr(effect.guard, 'value', None) is True)

    def _scan_callee_memory_outputs(
            self, effect, current, position, location, export_root, result):
        """Bind callee argument/global outputs that may define ``location``."""
        demand=self.demand
        engine=self.port.engine
        for callee in self.call_functions(effect):
            summary=self.summaries.get(callee)
            if summary is None:
                continue
            if summary.pending:
                result.append(TaintDependency('unknown',
                    'Incomplete callee memory summary: '+hex(callee),
                    uncertain=True))
            for slot, dependencies in summary.outputs:
                for address in self.argument(effect, slot):
                    target=self.location(address, effect.origin)
                    if target.object_id is not None:
                        target=engine.location(engine.roots[target.object_id],
                            None, 8, engine.architecture.endian, effect.origin)
                    alias=self.port.alias(
                        demand.initial.memory, target, location)
                    if alias.kind==AliasKind.NO:
                        continue
                    if export_root is not None and target.object_id!=export_root:
                        result.append(TaintDependency('unknown',
                            'Unproved callee argument-definition '
                            'correspondence at '+effect.origin,
                            uncertain=True))
                    else:
                        result.extend(self.bind_dependencies(
                            dependencies, effect, current, position, location))
            if summary.global_outputs is None:
                result.append(TaintDependency('unknown',
                    'Callee global export mode unavailable: '+hex(callee),
                    uncertain=True))
            for output in summary.global_outputs or ():
                target=global_output_location(self, output, effect.origin)
                if self.port.alias(
                        demand.initial.memory, target,
                        location).kind==AliasKind.NO:
                    continue
                if export_root is not None and target.object_id!=export_root:
                    result.append(TaintDependency('unknown',
                        'Global definition may alias argument; destination '
                        'correspondence unresolved', uncertain=True))
                else:
                    result.extend(self.bind_dependencies(output.dependencies,
                        effect, current, position, location))

    def _scan_procedure_call_effect(
            self, effect, current, position, reference, location,
            export_root, result):
        """Apply modeled call writes and detached callee memory summaries."""
        demand=self.demand
        rule=lookup(demand.call_name(effect))
        site=self.base+effect.site.point.instruction_rva
        modeled=('source_buffer', 'copy', 'format_output',
            'format_output_va_list', 'format_input')
        if rule and rule.operation in modeled:
            destinations=((rule.destination,) if rule.destination is not None
                else self.format_arguments(effect, rule))
            for slot in destinations:
                for target in self.argument(effect, slot):
                    destination=self.procedure_region(effect, rule, target)
                    if destination is None:
                        continue
                    alias=self.port.alias(
                        demand.initial.memory, destination, location)
                    if alias.kind==AliasKind.NO:
                        continue
                    if (export_root is not None and
                            destination.object_id!=export_root):
                        result.append(TaintDependency('unknown',
                            'Possible alias is not an argument-base '
                            'definition at '+effect.origin, uncertain=True))
                        continue
                    if rule.operation=='source_buffer':
                        result.append(self.source(effect, destination, rule))
                    elif rule.operation=='format_output_va_list':
                        copied=self.va_list_dependencies(
                            effect, current, position, rule)
                        lengths=self.constants(effect, rule.lengths)
                        if rule.lengths and not lengths:
                            lengths=('S',)
                        self.observe_sources(copied)
                        result.extend(replace(dep,
                            constraints=self.constraints(
                                dep.constraints, lengths),
                            uncertain=(dep.uncertain or
                                alias.kind!=AliasKind.MUST),
                            recipes=tuple(dict.fromkeys(
                                dep.recipes+
                                self.length_recipes(effect, rule))),
                            unresolved_constraints=(
                                dep.unresolved_constraints or
                                effect.origin in self.unresolved_recipe_calls))
                            for dep in copied)
                    else:
                        self._scan_procedure_copy_sources(
                            effect, rule, current, position, alias, result)
        self._scan_callee_memory_outputs(
            effect, current, position, location, export_root, result)
        callees=self.call_functions(effect)
        if rule is None and (
                not callees or any(f not in self.summaries for f in callees)):
            result.append(TaintDependency('unknown',
                'Unmodeled call memory effect at '+str(site), uncertain=True))
        if rule and rule.operation=='declared_unmodeled_source':
            result.append(TaintDependency('unknown',
                'Declared source has no original procedure model: '+rule.name,
                uncertain=True))
        if (rule and rule.operation=='hash_search' and
                self.constants(effect, (2,))!=(1,) and
                self.table_state.data_field_query(reference, effect)):
            for pointer in self.argument(effect, 4):
                result.extend(self.table_state.read(
                    self.table_state.root(pointer, effect.origin), effect))

    def _scan_procedure_copy_sources(
            self, effect, rule, current, position, alias, result):
        """Propagate copy/format input sources in their original loop order."""
        sources=((rule.source,) if rule.source is not None
            else self.format_arguments(effect, rule))
        lengths=self.constants(effect, rule.lengths)
        for source in sources:
            for value in self.argument(effect, source):
                copied=self.owner.buffer(
                    current, position, value, effect.origin)
                self.observe_sources(copied)
                unresolved=effect.origin in self.unresolved_recipe_calls
                if rule.operation=='copy' and rule.lengths:
                    if effect.origin in self.transfer_length_failures:
                        unresolved=True
                    else:
                        try:
                            length_dependencies=self.in_length_channel(
                                lambda:self.length_taint(
                                    effect, rule, current, position))
                            lengths=self.constraints(lengths,
                                uniform_copy_length_constraints(
                                    length_dependencies))
                        except DemandLimit as error:
                            if error.dimension not in ('alternatives', 'depth'):
                                raise
                            self.transfer_length_failures.add(effect.origin)
                            self.pending.append((effect.origin,
                                'Copy transfer length binding incomplete: '+
                                str(error)))
                            unresolved=True
                    if unresolved:
                        result.append(TaintDependency('unknown',
                            'Copy transfer length alternatives incomplete at '+
                            effect.origin, uncertain=True))
                result.extend(replace(dep,
                    constraints=self.constraints(dep.constraints, lengths),
                    uncertain=dep.uncertain or alias.kind!=AliasKind.MUST,
                    recipes=tuple(dict.fromkeys(
                        dep.recipes+self.length_recipes(effect, rule))),
                    unresolved_constraints=(
                        dep.unresolved_constraints or unresolved))
                    for dep in copied)

    def _entry_buffer_dependencies(
            self, location, reference, block, index, origin, whole_region,
            width_bits, byte_access, result):
        """Append caller argument/global requirements at the CFG entry."""
        engine=self.port.engine
        argument=next((slot for slot, root in
            getattr(engine, 'argument_roots', {}).items()
            if root.object_id==location.object_id), None)
        if argument is not None:
            result.append(TaintDependency('argument', argument,
                offset=None if whole_region else location.offset_lower,
                uncertain=whole_region, access_width=width_bits,
                byte_access=byte_access))
        else:
            result.extend(self.expression(reference, block, index, origin))
        absolute=self.port.concrete(reference)
        if type(absolute) is int and engine.address(absolute):
            permissions=next((flags for start, data, size, flags in
                getattr(engine, 'segments', ())
                if start<=absolute<start+size), None)
            # Immutable file-backed literals are not caller-mutable globals.
            if permissions is None or permissions&2:
                result.append(TaintDependency(
                    'global', absolute, uncertain=True))

    def _enqueue_buffer_predecessors(
            self, frontier, location, todo):
        """Enqueue feasible predecessors in the existing CFG order."""
        demand=self.demand
        for predecessor in demand.predecessors[frontier.block]:
            possible, policies=self.edge_policy(
                predecessor, frontier.block, location)
            if (not possible or
                    any(decision.kill for decision, _, _, _ in policies)):
                continue
            extra=tuple(value for decision, _, _, _ in policies
                for value in decision.constraints)
            evidence=tuple((source, relation, bound)
                for _, source, relation, bound in policies)
            todo.append(BufferFrontier(
                predecessor,
                len(demand.blocks[predecessor].effects),
                self.constraints(frontier.constraints, extra),
                tuple(sorted(set(frontier.guards+evidence))),
            ))

    def _decorate_frontier_dependencies(self, result, start, frontier):
        """Attach edge constraints/guards to rows added by one frontier."""
        result[start:]=[replace(dep,
            constraints=self.constraints(
                dep.constraints, frontier.constraints),
            guards=tuple(sorted(set(dep.guards+frontier.guards))))
            for dep in result[start:]]

    def buffer(self, block, index, reference, origin, *, whole_region=False,
               width_bits=8, byte_access=False, export_root=None):
        """Trace a memory requirement backwards without changing may rules."""
        self.tick()
        demand=self.demand
        node=self.port.engine.dag.nodes[reference]
        return_ops=('source_return', 'return_alias', 'integer_return',
            'stateful_token', 'deref_return')
        if (not byte_access and node.op==SymbolicOp.SYMBOL and
                node.value in demand.return_calls):
            rule=lookup(demand.call_name(demand.return_calls[node.value]))
            if rule and rule.operation in return_ops:
                return self.expression(reference, block, index, origin)
        location=self._normalize_buffer_location(
            reference, origin, whole_region, width_bits)
        key=(block, index, location.object_id, location.offset_lower,
            location.offset_upper, width_bits, byte_access,
            reference if location.object_id is None else None, export_root)
        if key in self.memo:
            return self.memo[key]
        if key in self.active:
            return (TaintDependency(
                'unknown', 'Recursive memory requirement', uncertain=True),)
        self.active.add(key)
        result=[]
        visited=set()
        todo=deque((BufferFrontier(block, index, (), ()),))
        try:
            while todo:
                frontier=todo.popleft()
                self.tick()
                if frontier in visited:
                    continue
                visited.add(frontier)
                killed=False
                start=len(result)
                effects=demand.blocks[frontier.block].effects
                for position in range(frontier.cutoff-1, -1, -1):
                    effect=effects[position]
                    if isinstance(effect, StoreEffect):
                        killed=self._scan_store_effect(effect, location,
                            frontier.block, position, byte_access, result)
                    elif isinstance(effect, CallEffect):
                        if all(demand.guard_concrete(g) is False
                               for g in demand.value(effect.guard)):
                            continue
                        self._scan_procedure_call_effect(effect,
                            frontier.block, position, reference, location,
                            export_root, result)
                    elif (isinstance(effect, UnknownEffect) and
                          effect.may_write_regions):
                        result.append(TaintDependency('unknown',
                            'Unsupported memory effect: '+effect.source_opcode,
                            uncertain=True))
                    if killed:
                        break
                if not killed:
                    if (frontier.block==self.function.entry or
                            not demand.predecessors[frontier.block]):
                        self._entry_buffer_dependencies(location, reference,
                            block, index, origin, whole_region, width_bits,
                            byte_access, result)
                    self._enqueue_buffer_predecessors(
                        frontier, location, todo)
                self._decorate_frontier_dependencies(
                    result, start, frontier)
            answer=self.union((result,))
            self.memo[key]=answer
            return answer
        finally:
            self.active.remove(key)

    def location(self, reference, origin):
        key=reference, origin
        if not self.cache_queries:return self._location(reference, origin)
        if key not in self.location_cache:self.location_cache[key]=self._location(reference, origin)
        return self.location_cache[key]

    def _location(self, reference, origin):
        engine=self.port.engine
        binding=self.demand.address_binding(reference)
        if binding:
            return engine.location(
                *binding, 8, engine.architecture.endian, origin)
        return engine.location(
            None, None, 8, engine.architecture.endian, origin)

    def procedure_region(self, call, rule, reference):
        p=self.port
        e=p.engine
        binding=self.demand.address_binding(reference)
        lengths=self.constants(call, rule.lengths)
        if lengths==(0,):return None
        if binding:
            root, offset=binding
            if offset is not None and lengths and 0<lengths[0] and offset+lengths[0]<(1<<e.architecture.pointer_bits):
                return e.location(root, offset, 8, e.architecture.endian, call.origin, upper=offset+lengths[0]-1)
            return e.location(root, None, 8, e.architecture.endian, call.origin)
        return e.location(None, None, 8, e.architecture.endian, call.origin)

    def destination(self, reference, origin):
        """Stable formal destination use/def, separate from source taint."""
        p=self.port
        e=p.engine
        binding=self.demand.address_binding(reference)
        if binding:
            root, offset=binding
            if root.region=='stack' and offset is not None:
                bits=e.architecture.pointer_bits
                signed=(offset+(1<<(bits-1)))%(1<<bits)-(1<<(bits-1))
                return (-signed,), ()
            for slot, argument in getattr(e, 'argument_roots', {}).items():
                if root.object_id==argument.object_id:return (), (BufferDestination('argument', slot, offset),)
        absolute=p.concrete(reference)
        if type(absolute) is int and e.address(absolute):return (), (BufferDestination('global', absolute),)
        # LegacyDemand's old DDG recurrence is base + stride*i. The old
        # forward pass also observes the first loop transfer; retain that
        # concrete MAY alongside the unbounded symbolic remainder. Only a
        # single, fully affine loop symbol with a resolved stack base qualifies.
        todo=[reference]
        seen=set()
        indices=set()
        while todo and len(seen)<128:
            item=todo.pop()
            if item in seen:continue
            seen.add(item)
            node=e.dag.nodes[item]
            if node.op==SymbolicOp.SYMBOL and node.value=='i':indices.add(item)
            else:todo.extend(node.operands)
        if not todo and len(indices)==1:
            affine=self.demand.affine(reference, next(iter(indices)))
            if affine is not None and affine[0]:
                bits=e.architecture.pointer_bits
                first=(affine[1]+affine[0])%(1<<bits)
                first_binding=self.demand.address_binding(p.constant(first, p.type_of(reference), origin))
                if first_binding and first_binding[0].region=='stack':
                    signed=(first_binding[1]+(1<<(bits-1)))%(1<<bits)-(1<<(bits-1))
                    return (-signed,), (BufferDestination('unknown', 'Unbounded loop destination '+origin, None),)
        return (), (BufferDestination('unknown', origin, None),)

    def edge_policy(self, predecessor, successor, location):
        """Recognize the original procedure-result guard on an exact pointer.

        Unrecognized guards and MayAlias never justify a kill. The descriptor
        records a legacy heuristic, not a proof that the path is feasible.
        """
        key=predecessor, successor, location.object_id, location.offset_lower
        if key in self.edge_policy_cache:return self.edge_policy_cache[key]
        p=self.port
        e=p.engine
        d=self.demand
        result=[]
        possible=True
        for effect in d.blocks[predecessor].effects:
            if not isinstance(effect, BranchEffect) or successor not in (effect.if_true, effect.if_false):continue
            polarity=successor==effect.if_true
            try:values=d.value(effect.condition)
            except DemandLimit as error:
                self.local_failure(error, effect.origin)
                continue
            if values and all(d.guard_concrete(v) is (not polarity) for v in values):
                possible=False
                break
            if len(values)!=1:continue
            ref=values[0]
            node=e.dag.nodes[ref]
            while node.op in (SymbolicOp.COPY, SymbolicOp.NOT):
                if node.op==SymbolicOp.NOT:polarity=not polarity
                ref=node.operands[0]
                node=e.dag.nodes[ref]
            if node.op not in (SymbolicOp.EQ, SymbolicOp.ULT, SymbolicOp.SLT):continue
            left, right=node.operands
            bound=d.guard_concrete(right)
            relation='eq' if node.op==SymbolicOp.EQ else 'lt'
            if type(bound) is not int:
                bound=d.guard_concrete(left)
                left=right
                relation='eq' if node.op==SymbolicOp.EQ else 'gt'
            if type(bound) is not int:continue
            if not polarity:relation={'eq':'ne', 'lt':'ge', 'gt':'le'}[relation]
            value=e.dag.nodes[left]
            while value.op in (SymbolicOp.COPY, SymbolicOp.ZERO_EXTEND, SymbolicOp.SIGN_EXTEND):
                left=value.operands[0]
                value=e.dag.nodes[left]
            if value.op!=SymbolicOp.SYMBOL or value.value not in d.return_calls:continue
            call=d.return_calls[value.value]
            rule=lookup(d.call_name(call))
            if not rule or not rule.constraint_type:continue
            slots=(0, 1) if rule.name in ('strcmp', 'strcasecmp', 'stricmp') else (rule.source,)
            for slot in slots:
                if slot is None:continue
                for address in self.argument(call, slot):
                    source=self.location(address, call.origin)
                    if p.alias(d.initial.memory, source, location).kind!=AliasKind.MUST:continue
                    decision=legacy_constraint(rule.constraint_type, relation, bound)
                    result.append((decision, effect.origin, relation, bound))
        answer=possible, tuple(result)
        self.edge_policy_cache[key]=answer
        return answer

