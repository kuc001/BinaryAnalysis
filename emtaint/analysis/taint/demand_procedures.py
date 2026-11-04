"""Behavior-preserving P7 procedures component."""


from collections import Counter, deque
from dataclasses import replace
from typing import Protocol

from emtaint.analysis.dataflow.legacy_demand import (
    ArgumentRead,
    DemandLimit,
)
from emtaint.core.contracts import ValueType
from emtaint.ir.canonical import CallEffect, StoreEffect
from emtaint.memory import SymbolicOp
from emtaint.procedures.legacy import (
    legacy_format_parameters,
    lookup,
    uniform_copy_length_constraints,
)

from .demand_models import (
    DeferredFormatArgument,
    SinkRequirement,
    TaintDependency,
    dependency_order,
)


MAX_FORMAT_BYTES = 4096
MAX_ARGV_SLOTS = 256


class ProcedureOwner(Protocol):
    """Structural owner contract; analysis state remains on the facade."""

    pass


class DemandProcedures:
    """Own procedures operations while delegating shared state to the facade."""

    def __init__(self, owner: ProcedureOwner) -> None:
        object.__setattr__(self, "owner", owner)

    def __getattr__(self, name: str) -> object:
        return getattr(self.owner, name)

    def __setattr__(self, name: str, value: object) -> None:
        setattr(self.owner, name, value)

    def _resolve_va_list_bases(self, call, rule, trace, groups):
        """Resolve va_list entry bindings and retain one row per actual."""
        bases=[]
        for va_list in self.argument(call, rule.source):
            base=self.demand.address_binding(va_list)
            trace['bases'].append(str(base))
            if base is None or base[1] is None:
                groups.append((TaintDependency('unknown',
                    'vsnprintf va_list base unresolved at '+call.origin,
                    uncertain=True),))
                continue
            bases.append(base)
        return bases

    def _collect_va_list_store_candidates(
            self, base, block, index, string_indexes, format_slots, trace):
        """Collect legacy base/base+constant Stores in reverse CFG order."""
        demand=self.demand
        pointer_bits=self.port.engine.architecture.pointer_bits
        word=pointer_bits//8
        mask=(1<<pointer_bits)-1
        todo=deque(((block, index),))
        seen=set()
        addresses={}
        unresolved=False
        while todo:
            current, cutoff=todo.popleft()
            if (current, cutoff) in seen:
                continue
            seen.add((current, cutoff))
            for effect in reversed(demand.blocks[current].effects[:cutoff]):
                if (not isinstance(effect, StoreEffect) or
                        getattr(effect.guard, 'value', None) is False):
                    continue
                binding=demand.local_address(effect.address)
                if binding is None or binding[1] is None:
                    # A copied frame register may still prove an entry-SP
                    # offset even when the generic local classifier is open.
                    exact=demand.exact_stack_address(effect.address)
                    if exact is not None:
                        binding=exact
                if len(trace['stores'])<64:
                    trace['stores'].append({
                        'origin':effect.origin,
                        'binding':str(binding),
                        'same_object':bool(binding and
                            binding[0].object_id==base[0].object_id),
                    })
                if binding is None:
                    unresolved=True
                    continue
                if binding[0].object_id!=base[0].object_id:
                    continue
                if binding[1] is None:
                    unresolved=True
                    continue
                offset=(binding[1]-base[1])&mask
                # This is intentionally not a conventional argument index.
                position=offset%word
                if position not in string_indexes and not format_slots:
                    continue
                addresses[(binding[0].object_id, binding[1])]=(
                    effect.address, position)
            todo.extend((pre, len(demand.blocks[pre].effects))
                for pre in demand.predecessors[current])
        return addresses, unresolved

    def _read_va_list_dependencies(
            self, addresses, call, block, index, read, string_indexes,
            format_unresolved, format_slots, trace, groups):
        """Read candidate Stores and append concrete/deferred dependencies."""
        demand=self.demand
        for operand, position in addresses.values():
            for address in demand.value(operand):
                try:
                    pointers=demand.read(block, index, address, read, 0)
                except DemandLimit as error:
                    groups.append((self.local_failure(error, call.origin),))
                    continue
                for pointer in pointers:
                    if demand.guard_concrete(pointer)==0:
                        continue
                    dependencies=self.buffer(
                        block, index, pointer, call.origin)
                    if len(trace['reads'])<64:
                        trace['reads'].append({
                            'store':(demand.loads.get(pointer, ('',))[0]
                                if pointer in demand.loads else None),
                            'position':position,
                            'dependency_kinds':tuple(
                                dep.kind for dep in dependencies),
                        })
                    if position in string_indexes:
                        groups.append(dependencies)
                    if format_unresolved:
                        for slot in sorted(format_slots):
                            groups.append(tuple(TaintDependency(
                                'format_argument',
                                DeferredFormatArgument(
                                    slot, position, dependency),
                                uncertain=True,
                                unresolved_constraints=True)
                                for dependency in dependencies))

    def va_list_dependencies(self, call, block, index, rule):
        """Apply old vsnprintf Store/va_list matching through versioned reads.

        Store offsets select format positions using ``offset % arch.bytes``.
        That unusual historical rule and all unresolved may paths are kept.
        """
        engine=self.port.engine
        groups=[]
        trace={
            'origin':call.origin,
            'format_indexes':(),
            'format_unresolved':False,
            'format_slots':(),
            'bases':[],
            'stores':[],
            'reads':[],
        }
        string_indexes, format_unresolved=self.owner.format_string_indexes(
            call, rule)
        trace['format_indexes']=string_indexes
        trace['format_unresolved']=format_unresolved
        if format_unresolved:
            groups.append((TaintDependency('unknown',
                'vsnprintf format/va_list correspondence unresolved',
                uncertain=True),))
        format_slots=set()
        if format_unresolved:
            for value in self.argument(call, rule.format_index):
                for dependency in self.scalar_expression(
                        value, block, index, call.origin):
                    if (dependency.kind in ('argument', 'scalar_argument') and
                            type(dependency.value) is int):
                        format_slots.add(dependency.value)
        trace['format_slots']=tuple(sorted(format_slots))
        if not string_indexes and not format_slots:
            self.va_list_diagnostics.append(trace)
            return self.union(groups)
        read=ArgumentRead(engine.architecture.pointer_bits,
            engine.architecture.endian, call.origin)
        bases=self._resolve_va_list_bases(call, rule, trace, groups)
        for base in bases:
            addresses, unresolved=self._collect_va_list_store_candidates(
                base, block, index, string_indexes, format_slots, trace)
            self._read_va_list_dependencies(addresses, call, block, index,
                read, string_indexes, format_unresolved, format_slots,
                trace, groups)
            if unresolved:
                groups.append((TaintDependency('unknown',
                    'vsnprintf Store/va_list alias unresolved at '+call.origin,
                    uncertain=True),))
        self.va_list_diagnostics.append(trace)
        return self.union(groups)

    def _query_hash_call(self, effect, rule, block, index):
        """Apply the legacy hsearch FIND/INSERT may model."""
        actions=self.constants(effect, (2,))
        roots=tuple(self.table_state.root(value, effect.origin)
            for value in self.argument(effect, 4))
        if actions!=(1,):
            for root in roots:
                for return_pointer in self.argument(effect, 3):
                    self.table_state.find(root, effect, return_pointer)
        if actions!=(0,):
            dependencies=self.union(self.buffer(
                block, index, value, effect.origin)
                for value in self.argument(effect, 1))
            for root in roots:
                self.table_state.write(root, dependencies, effect)
        if not actions:
            self.diagnostics.append(
                'hsearch_r action unknown; FIND/INSERT retained as may at '+
                effect.origin)

    def _local_sink_shape(self, effect, rule, site):
        """Create the sink shell before any interruptible dependency query."""
        slots=((rule.source,) if rule.source is not None
            else self.format_arguments(effect, rule))
        if rule.name=='_system':
            slots+=self.format_arguments(effect, rule)
        offsets=[]
        destination_requirements=[]
        destinations=((rule.destination,)
            if rule.destination is not None
            else self.format_arguments(effect, rule)
            if rule.operation=='format_input' else ())
        for slot in destinations:
            for value in self.argument(effect, slot):
                sizes, requirements=self.destination(value, effect.origin)
                offsets.extend(sizes)
                destination_requirements.extend(requirements)
        constraints=self.constants(effect, rule.lengths)
        if (rule.lengths and not constraints and
                rule.operation=='format_output'):
            constraints=('S',)
        bounded=rule.operation=='copy' and bool(rule.lengths)
        sink=SinkRequirement(
            self.base+self.function.function_id.rva,
            site,
            rule.name,
            ('command' if rule.operation in ('command', 'command_argv')
                else 'copy'),
            tuple(sorted(set(offsets))),
            (),
            effect.origin,
            constraints,
            tuple(g.key for g in self.demand.value(effect.guard)),
            tuple(sorted(set(destination_requirements), key=repr)),
            weak_kind=('copy_length' if bounded else 'command'
                if rule.operation.startswith('command') else 'copy'),
            length_dependencies=(TaintDependency('unknown',
                'Length-taint analysis pending', uncertain=True),)
                if bounded else (),
        )
        return slots, constraints, bounded, sink

    def _resolve_local_sink_dependencies(
            self, effect, rule, block, index, slots):
        """Resolve a sink data channel while retaining partial Sources."""
        try:
            dependencies=(self.argv_dependencies(effect, block, index)
                if rule.operation=='command_argv' else
                self.union(self.buffer(block, index, value, effect.origin)
                    for slot in slots
                    for value in self.argument(effect, slot)))
        except DemandLimit as error:
            if error.dimension not in ('alternatives', 'depth'):
                raise
            self.pending.append((effect.origin,
                'Local sink binding incomplete: '+str(error)))
            known=tuple(sorted(
                self.partial_sources|self.query_sources,
                key=dependency_order))
            self.local_recoveries.append({
                'origin':effect.origin,
                'stage':'buffer',
                'known':len(known),
                'kinds':dict(sorted(
                    Counter(dep.kind for dep in known).items())),
            })
            dependencies=known+(TaintDependency('unknown',
                'Local sink alternatives incomplete at '+effect.origin,
                uncertain=True),)
        dependencies=tuple(replace(dep,
            recipes=tuple(dict.fromkeys(
                dep.recipes+self.length_recipes(effect, rule))),
            unresolved_constraints=(dep.unresolved_constraints or
                effect.origin in self.unresolved_recipe_calls))
            for dep in dependencies)
        unknown_format=any(
            'Unknown format at '+effect.origin==note.split(';')[0]
            for note in self.diagnostics)
        if rule.format_index is not None and unknown_format:
            dependencies=tuple(dict.fromkeys(dependencies+
                (TaintDependency('unknown', 'Unknown format argument set',
                    uncertain=True),)))
        self.active_sink=replace(
            self.active_sink, dependencies=dependencies)

    def _resolve_local_sink_lengths(
            self, effect, rule, block, index, constraints):
        """Resolve the independent length channel with partial recovery."""
        try:
            lengths=self.in_length_channel(
                lambda:self.length_taint(effect, rule, block, index))
            bounds=uniform_copy_length_constraints(lengths)
            self.active_sink=replace(self.active_sink,
                length_dependencies=lengths,
                constraints=self.constraints(constraints, bounds))
        except DemandLimit as error:
            if error.dimension not in ('alternatives', 'depth'):
                raise
            self.pending.append((effect.origin,
                'Local sink length binding incomplete: '+str(error)))
            lengths=self.active_sink.length_dependencies
            if not lengths:
                lengths=(TaintDependency('unknown',
                    'Local sink length alternatives incomplete at '+
                    effect.origin, uncertain=True),)
            elif not any(dep.kind=='unknown' for dep in lengths):
                lengths=lengths+(TaintDependency('unknown',
                    'Local sink length alternatives incomplete at '+
                    effect.origin, uncertain=True),)
            self.local_recoveries.append({
                'origin':effect.origin,
                'stage':'length',
                'buffer_dependencies':len(self.active_sink.dependencies),
                'buffer_kinds':dict(sorted(Counter(
                    dep.kind for dep in
                    self.active_sink.dependencies).items())),
                'length_dependencies':len(lengths),
                'length_kinds':dict(sorted(
                    Counter(dep.kind for dep in lengths).items())),
            })
            self.active_sink=replace(
                self.active_sink, length_dependencies=lengths)

    def _commit_local_sink(self, effect):
        """Record recovery metrics and publish the current sink shell."""
        self.local_recoveries.append({
            'origin':effect.origin,
            'stage':'commit',
            'buffer_dependencies':len(self.active_sink.dependencies),
            'buffer_kinds':dict(sorted(Counter(
                dep.kind for dep in self.active_sink.dependencies).items())),
        })
        self.add_sink(self.active_sink)

    def local_call_query(self, effect, block, index):
        """Execute one local procedure query without losing partial sinks."""
        rule=lookup(self.demand.call_name(effect))
        site=self.base+effect.site.point.instruction_rva
        if rule and rule.operation=='legacy_trace_source':
            self.pending.append((effect.origin,
                'Legacy SSL_read backward 0x100 trace has no Source ID; '
                'transfer not yet migrated'))
            return
        if rule and rule.operation=='format_output_va_list':
            _, unresolved=self.format_string_indexes(effect, rule)
            if unresolved:
                self.pending.append((effect.origin,
                    'Legacy vsnprintf format/va_list correspondence remains '
                    'incomplete'))
            return
        if rule and rule.operation=='hash_search':
            self._query_hash_call(effect, rule, block, index)
        sink_operations=(
            'copy', 'format_output', 'format_input', 'command', 'command_argv')
        if not rule or rule.operation not in sink_operations:
            return
        slots, constraints, bounded, sink=self._local_sink_shape(
            effect, rule, site)
        self.active_sink=sink
        self.partial_sources=set()
        self._resolve_local_sink_dependencies(
            effect, rule, block, index, slots)
        if bounded:
            self._resolve_local_sink_lengths(
                effect, rule, block, index, constraints)
        self._commit_local_sink(effect)

    def format_arguments(self, call, rule):
        key=call.origin, rule
        if key not in self.format_cache:self.format_cache[key]=self._format_arguments(call, rule)
        return self.format_cache[key]

    def _format_arguments(self, call, rule):
        indexes, _=self.owner.format_string_indexes(call, rule)
        return tuple(rule.variadic_start+i for i in indexes) if rule.variadic_start is not None else ()

    def format_string_indexes(self, call, rule):
        """Return old FormatParser string positions and an unresolved flag."""
        key=call.origin, rule
        if key not in self.format_descriptor_cache:
            self.format_descriptor_cache[key]=self._format_string_indexes(call, rule)
        return self.format_descriptor_cache[key]

    def _format_string_indexes(self, call, rule):
        if rule.format_index is None:return (), False
        return self.format_value_indexes(self.argument(call, rule.format_index), call.origin)

    def format_value_indexes(self, addresses, origin, *, diagnose=True):
        """Parse concrete format values without assuming an external call ABI."""
        p=self.port
        e=p.engine
        strings=[]
        unresolved=False
        for address in addresses:
            base=p.concrete(address)
            if type(base) is not int:
                unresolved=True
                continue
            data=[]
            terminated=False
            for i in range(MAX_FORMAT_BYTES):
                binding=e.address(base+i)
                if binding is None:break
                loc=e.location(*binding, 8, e.architecture.endian, origin)
                read=p.read(
                    self.demand.initial.memory,
                    loc,
                    p.constant(True, ValueType.boolean(), origin),
                    origin,
                ).value
                value=p.guard_concrete(read)
                if value is None:
                    # Retain the original FormatParser loader interpretation
                    # as one possible format, together with an explicit unknown
                    # remainder. It cannot prove a runtime bound or clean flow.
                    unresolved=True
                    value=p.concrete(read)
                if value is None:break
                if value==0:
                    terminated=True
                    break
                data.append(value)
            if terminated:strings.append(bytes(data))
            else:unresolved=True
        if diagnose and (unresolved or not strings):
            note='Unknown format at '+origin+'; variadic coverage incomplete'
            if note not in self.diagnostics:self.diagnostics.append(note)
        indexes=tuple(sorted({
            i
            for data in strings
            for i, kind in enumerate(legacy_format_parameters(data))
            if kind=='s'
        }))
        return indexes, unresolved or not strings

    def argv_dependencies(self, call, block, index):
        """Old argv Store-slot / zero-terminator rule, with versioned reads."""
        p=self.port
        e=p.engine
        d=self.demand
        word=e.architecture.pointer_bits//8
        groups=[]
        contexts=[(block, index)]+[(pre, len(d.blocks[pre].effects)) for pre in d.predecessors[block]]
        for argv in self.argument(call, 1):
            base=d.address_binding(argv)
            ends=set()
            if base and base[1] is not None:
                for current, cutoff in contexts:
                    for effect in reversed(d.blocks[current].effects[:cutoff]):
                        if (not isinstance(effect, StoreEffect) or
                                effect.width_bits!=word*8 or
                                getattr(effect.guard, 'value', None) is not True):
                            continue
                        if not all(d.guard_concrete(value)==0 for value in d.value(effect.value)):continue
                        target=d.local_address(effect.address)
                        if not target or target[0]!=base[0] or target[1] is None:continue
                        offset=(target[1]-base[1])%(1<<e.architecture.pointer_bits)
                        if (offset%word==0 and
                                0<offset//word<=MAX_ARGV_SLOTS):
                            ends.add(offset//word)
                            break
            if not ends:
                groups.append((TaintDependency(
                    'unknown',
                    'execve argv terminator correspondence unresolved',
                    uncertain=True,
                ),))
                continue
            for slot in range(max(ends)):
                delta=p.constant(slot*word, p.type_of(argv), call.origin)
                address=p.operation(SymbolicOp.ADD, p.type_of(argv), (argv, delta), call.origin)
                read=ArgumentRead(word*8, e.architecture.endian, call.origin)
                for pointer in d.read(block, index, address, read, 0):
                    if d.guard_concrete(pointer)==0:continue
                    groups.append(self.buffer(block, index, pointer, call.origin))
        return self.union(groups)


    def token_dependencies(self, call, block, index):
        """Session-local backward use/def for old strtok's r1001 SAVE_PTR."""
        p=self.port
        d=self.demand
        arguments=self.argument(call, 0)
        choices={d.guard_concrete(v) for v in arguments}
        groups=[]
        if choices!={0}:
            groups.extend(self.buffer(
                block, index, value, call.origin)
                for value in arguments if d.guard_concrete(value)!=0)
        if 0 not in choices and None not in choices:return self.union(groups)
        if None in choices:
            groups.append((TaintDependency(
                'unknown',
                'strtok new/saved pointer choice unresolved',
                uncertain=True,
            ),))
        todo=deque(((block, index),))
        seen=set()
        while todo:
            current, cutoff=todo.popleft()
            self.tick()
            if (current, cutoff) in seen:
                groups.append((TaintDependency('unknown', 'strtok saved pointer loop frontier', uncertain=True),))
                continue
            seen.add((current, cutoff))
            defined=False
            for position in range(cutoff-1, -1, -1):
                previous=d.blocks[current].effects[position]
                if not isinstance(previous, CallEffect):continue
                rule=lookup(d.call_name(previous))
                if rule is None:
                    groups.append((TaintDependency(
                        'unknown',
                        'Unmodeled call may change strtok saved pointer',
                        uncertain=True,
                    ),))
                    continue
                if rule.operation!='stateful_token':continue
                guards={d.guard_concrete(g) for g in d.value(previous.guard)}
                if guards=={False}:continue
                values=self.argument(previous, 0)
                prior={d.guard_concrete(v) for v in values}
                if prior=={0}:continue
                groups.extend(self.buffer(
                    current, position, value, previous.origin)
                    for value in values if d.guard_concrete(value)!=0)
                if None not in prior and 0 not in prior and guards=={True}:
                    defined=True
                    break
                groups.append((TaintDependency(
                    'unknown',
                    'strtok saved pointer conditional definition',
                    uncertain=True,
                ),))
            if not defined:
                if current==self.function.entry or not d.predecessors[current]:
                    groups.append((TaintDependency(
                        'unknown',
                        'strtok saved pointer uninitialized in this context',
                        uncertain=True,
                    ),))
                todo.extend((pre, len(d.blocks[pre].effects)) for pre in d.predecessors[current])
        return self.union(groups)
