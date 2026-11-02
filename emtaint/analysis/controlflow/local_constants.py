"""Exact block-local scalar constants for VEX's explicit PC assignments."""
from dataclasses import replace
from itertools import product
from emtaint.core.contracts import Constant
from emtaint.ir.canonical import Compute, ReadRegister, WriteRegister, CallEffect, JumpEffect, UnknownEffect
from emtaint.graph import FlowEdge, FlowKind


def local_terminal_constants(function, image_base):
    """Native block-local target values; no IDA target is used as a seed."""
    terminals={}
    for block in function.blocks:
        values={}
        registers={}
        def operand(x):return (x.value,) if isinstance(x, Constant) else values.get(x.id, ())
        for effect in block.effects:
            if isinstance(effect, Compute):
                groups=[operand(x) for x in effect.args]
                result=set()
                if effect.op.value=='if':
                    guards=groups[0]
                    if not guards or True in guards:result.update(groups[1])
                    if not guards or False in guards:result.update(groups[2])
                elif all(groups) and all(len(g)<=4 for g in groups):
                    for a in product(*groups):
                        name=effect.op.value
                        if name=='copy':v=a[0]
                        elif name=='add':v=a[0]+a[1]
                        elif name=='sub':v=a[0]-a[1]
                        elif name=='and_bits':v=a[0]&a[1]
                        elif name=='or_bits':v=a[0]|a[1]
                        elif name=='xor_bits':v=a[0]^a[1]
                        else:continue
                        result.add(v%(1<<effect.result.type.bits))
                values[effect.result.id]=tuple(result)
            elif isinstance(effect, ReadRegister):
                if effect.source.bit_offset==0 and effect.source.width_bits==effect.source.register_width_bits:
                    values[effect.result.id]=registers.get(effect.source.register, ())
            elif isinstance(effect, WriteRegister):
                if effect.target.bit_offset==0 and effect.target.width_bits==effect.target.register_width_bits:
                    guard=operand(effect.guard)
                    new=operand(effect.value)
                    if guard==(True,):registers[effect.target.register]=new
                    elif guard!=(False,):registers[effect.target.register]=tuple(set(new)|set(registers.get(effect.target.register, ())))
            elif isinstance(effect, (CallEffect, UnknownEffect)):
                clobbers=effect.footprint.clobbered_registers if isinstance(effect, CallEffect) else effect.may_write_registers
                if '*' in clobbers:registers.clear()
                else:
                    for name in clobbers:registers.pop(name, None)
            elif isinstance(effect, JumpEffect):
                terminals[effect.origin]=((effect.target.rva+image_base,) if hasattr(effect.target, 'function') else operand(effect.target))
    return terminals


def local_constant_edges(function, cfg, image_base):
    by_address={b.id.rva+image_base:b.id for b in function.blocks if b.id.index==0}
    edges=set(cfg.edges)
    terminals=local_terminal_constants(function, image_base)
    for block in function.blocks:
        for effect in block.effects:
            if not isinstance(effect, JumpEffect):continue
            for absolute in terminals.get(effect.origin, ()):
                target=by_address.get(absolute)
                if target is not None:edges.add(FlowEdge(block.id, target, FlowKind.JUMP, 'Exact block-local PC constant'))
    return replace(cfg, edges=frozenset(edges))


def ida_metadata_edges(function, cfg, mappings, source_edges, image_base):
    """Preserve the original IDA CFG through native block splitting.

    These are source-CFG may edges, with explicit provenance. They must not
    erase CIR guards or be relabeled as independently proved native edges.
    """
    blocks={b.id.token:b.id for b in function.blocks}
    groups={}
    for row in mappings:
        if row['function']==function.function_id.rva+image_base:
            groups.setdefault(row['source_start'], []).append(row)
    edges=set(cfg.edges)
    for source, target in source_edges:
        if source not in groups or target not in groups:continue
        first=min(groups[target], key=lambda x:x['irsb_start'])
        last=max(groups[source], key=lambda x:x['irsb_start'])
        if not first['cir_blocks'] or not last['cir_blocks']:continue
        a, b=blocks[last['cir_blocks'][-1]], blocks[first['cir_blocks'][0]]
        if not any(e.source==a and e.target==b for e in edges):
            edges.add(FlowEdge(a, b, FlowKind.UNKNOWN, 'Original IDA CFG edge; CIR source-block split mapping'))
    return replace(cfg, edges=frozenset(edges))
