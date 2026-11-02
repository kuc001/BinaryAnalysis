"""Old global-definition export, with detached geometry and actual CIR order.

The old FastSearch _get_argument_def_exprs exports integer-base global defs.
These descriptors preserve the writing location, rather than relabeling every
MayAlias argument as the definition's destination. All correspondence queries
and caller projections still use MemoryQueryPort and the P5 memory contract.
"""
from dataclasses import dataclass, replace
from emtaint.core import Endian
from emtaint.core.contracts import ValueType
from emtaint.ir.canonical import StoreEffect, CallEffect
from emtaint.procedures.legacy import lookup


@dataclass(frozen=True)
class GlobalTaintOutput:
    address:int
    width_bits:int
    endian:Endian
    span:int|None
    origin:str
    dependencies:tuple=()

    def __post_init__(self):
        if type(self.address) is not int or self.address<0:raise ValueError('Invalid global output address')
        if type(self.width_bits) is not int or self.width_bits<8 or self.width_bits%8:raise ValueError('Invalid global output width')
        if not isinstance(self.endian, Endian):raise ValueError('Invalid global output endian')
        if self.span is not None and (type(self.span) is not int or self.span<1):raise ValueError('Invalid global output span')
        if type(self.origin) is not str or not self.origin:raise ValueError('Missing global output origin')


def output_order(value):return value.address, value.width_bits, value.endian.value, repr(value.span)


def location(owner, output, origin):
    e=owner.port.engine
    binding=e.address(output.address)
    if binding is None:raise ValueError('Global output is outside the matching image')
    root, offset=binding
    if root.region!='global':raise ValueError('Global output does not name a global object')
    return e.location(root, None if output.span is None else offset, output.width_bits, output.endian, origin,
        upper=None if output.span is None else offset+output.span-1)


def candidates(owner, block, index, effect):
    d=owner.demand
    p=owner.port
    e=p.engine
    if all(d.guard_concrete(value) is False for value in d.value(effect.guard)):return ()
    result=[]
    def destination(reference, width, endian, span):
        binding=d.address_binding(reference)
        if binding is not None and binding[0].region!='global':return
        absolute=p.concrete(reference)
        actual=e.address(absolute) if type(absolute) is int else None
        if actual is None or actual[0].region!='global':
            note=(effect.origin, 'Global output destination unresolved; memory effects remain incomplete')
            if note not in owner.pending:owner.pending.append(note)
            return
        result.append(GlobalTaintOutput(absolute, width, endian, span, effect.origin))
    if isinstance(effect, StoreEffect):
        for reference in d.value(effect.address):destination(reference, effect.width_bits, effect.endian, 1)
    elif isinstance(effect, CallEffect):
        rule=lookup(d.call_name(effect))
        if rule and rule.operation in ('source_buffer', 'copy', 'format_output', 'format_output_va_list', 'format_input'):
            slots=(rule.destination,) if rule.destination is not None else owner.format_arguments(effect, rule)
            lengths=owner.constants(effect, rule.lengths)
            if lengths==(0,):return ()
            span=lengths[0] if lengths and lengths[0]>0 else None
            for slot in slots:
                for reference in owner.argument(effect, slot):destination(reference, 8, e.architecture.endian, span)
        if rule is not None:return tuple(sorted(set(result), key=output_order))
        for callee in owner.call_functions(effect):
            summary=owner.summaries.get(callee)
            if summary is None or summary.global_outputs is None:
                note=(effect.origin, 'Callee global export mode unavailable; memory effects remain incomplete')
                if note not in owner.pending:owner.pending.append(note)
            else:
                if summary.pending:
                    note=(effect.origin, 'Incomplete callee may have additional global definitions')
                    if note not in owner.pending:owner.pending.append(note)
                result.extend(replace(output, origin=effect.origin, dependencies=()) for output in summary.global_outputs)
    return tuple(sorted(set(result), key=output_order))


def definitions(owner):
    for block in owner.function.blocks:
        for index, effect in enumerate(block.effects):
            if isinstance(effect, StoreEffect):yield block.id, index, effect
            elif isinstance(effect, CallEffect):
                rule=lookup(owner.demand.call_name(effect))
                if (rule is None and owner.call_functions(effect)) or (rule and rule.operation in ('source_buffer', 'copy', 'format_output', 'format_output_va_list', 'format_input')):
                    yield block.id, index, effect


def query(owner, definition, exit_block, exit_index, exit_origin):
    for output in candidates(owner, *definition):
        owner.active_global_output=output
        owner.query_sources=set()
        owner.partial_sources=set()
        reference=owner.port.constant(output.address, ValueType.bv(owner.port.engine.architecture.pointer_bits), exit_origin)
        values=owner.buffer(exit_block, exit_index, reference, exit_origin, width_bits=output.width_bits, byte_access=True)
        # Entry-state requirements are not new writes to export. Other globals,
        # formal values and unknown effects remain real dependencies.
        values=tuple(value for value in values if not(value.kind=='global' and value.value==output.address))
        if values:owner.add_global_output(replace(output, dependencies=values))
        owner.active_global_output=None
