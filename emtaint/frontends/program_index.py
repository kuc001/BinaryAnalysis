"""Read-only IDA/CIR adapter for the complete single-image dependency graph."""
from dataclasses import dataclass
from emtaint.core import (Program, Function, BasicBlock, FunctionId, BlockId, ProgramPoint,
                         CallSiteId, CallSite, CallKind, Completeness)
from emtaint.ir.canonical import CallEffect, DirectTarget, IndirectTarget, JumpEffect, ReturnEffect
from emtaint.graph import CallGraph, CallEdge, TargetKind, ControlFlowGraph, FlowEdge, FlowKind


@dataclass(frozen=True)
class ProgramIndex:
    program:object
    cg:object
    cfgs:tuple
    external_calls:tuple
    native_only_calls:tuple


def build_program_index(module, specifications, image_base, *, input_sites=(), native_cfgs=()):
    binary=module.functions[0].function_id.binary
    bodies={f.function_id:f for f in module.functions}
    origins={o.id:o for o in module.origin_map}
    specs={FunctionId(binary, s.address-image_base):s for s in specifications}
    declared=set(specs)
    declared.update(FunctionId(binary, c.target-image_base) for s in specifications for c in s.calls
                    if type(c.target) is int and c.target>=image_base and any(b.start==c.block and not b.boundary for b in s.blocks))
    native_sites={}
    sites={}
    edges=set()
    external=[]
    metadata_locations=set()
    for function in module.functions:
        for block in function.blocks:
            for effect in block.effects:
                if isinstance(effect, CallEffect):
                    location=(function.function_id, effect.site.point.instruction_rva)
                    native_sites[location]=effect.site
                    indirect=isinstance(effect.target, IndirectTarget)
                    sites[effect.site]=CallSite(effect.site, CallKind.INDIRECT if indirect else CallKind.DIRECT)
                    if isinstance(effect.target, DirectTarget):
                        declared.add(effect.target.function)
                        edges.add(CallEdge(effect.site, effect.target.function, TargetKind.CONFIRMED,
                            'Native CIR direct call target'))
                    elif indirect:
                        edges.add(CallEdge(effect.site, None, TargetKind.UNKNOWN,
                            'Native CIR indirect call; unresolved remainder'))
    points={}
    for origin in module.origin_map:
        if origin.point.instruction_rva is not None:points.setdefault((origin.point.function, origin.point.instruction_rva), origin.point)
    for function in module.functions:
        for block in function.blocks:
            for effect in block.effects:
                if isinstance(effect, (CallEffect, JumpEffect, ReturnEffect)):
                    point=origins[effect.origin].point
                    if point.instruction_rva is not None:points[point.function, point.instruction_rva]=point
    for fid, spec in specs.items():
        for call in spec.calls:
            if not any(b.start==call.block and not b.boundary for b in spec.blocks):continue
            location=(fid, call.instruction-image_base)
            metadata_locations.add(location)
            site=native_sites.get(location)
            if site is None:
                point=points.get(location, ProgramPoint(BlockId(fid, call.block-image_base), None, call.instruction-image_base))
                site=CallSiteId(point)
            kind=CallKind.DIRECT if type(call.target) is int else CallKind.UNKNOWN
            sites[site]=CallSite(site, kind)
            if type(call.target) is int and call.target>=image_base:
                target=FunctionId(binary, call.target-image_base)
                edges.add(CallEdge(site, target, TargetKind.CONFIRMED, 'Original IDA static call metadata'))
            else:
                edges.add(CallEdge(site, None, TargetKind.UNKNOWN, 'Original IDA external/unknown call: '+str(call.target)))
                external.append((fid, site, str(call.target)))
    for caller, address in input_sites:
        fid=FunctionId(binary, caller-image_base)
        location=(fid, address-image_base)
        point=points.get(location)
        if point is None:raise ValueError('IDA iCall annotation has no CIR origin')
        site=native_sites.get(location, CallSiteId(point))
        sites[site]=CallSite(site, CallKind.INDIRECT)
        if not any(e.site==site for e in edges):edges.add(CallEdge(site, None, TargetKind.UNKNOWN, 'Original IDA iCall annotation; unresolved remainder'))
    native_only=[]
    for location, site in native_sites.items():
        if location not in metadata_locations:
            native_only.append(site)
            if not any(e.site==site for e in edges):edges.add(CallEdge(site, None, TargetKind.UNKNOWN, 'CIR call not present in original IDA call table'))
    functions=[]
    cfgs=[]
    native_cfgs={g.function:g for g in native_cfgs}
    by_block={}
    for origin in module.origin_map:
        if origin.point.instruction_rva is not None:by_block.setdefault(origin.point.block, []).append(origin.point.instruction_rva)
    for fid in sorted(declared, key=lambda f:f.rva):
        body=bodies.get(fid)
        spec=specs.get(fid)
        if body:
            blocks=tuple(BasicBlock(b.id, max(b.size_bytes or 1, max(by_block.get(b.id, (b.id.rva,)))-b.id.rva+1)) for b in body.blocks)
            entry=body.entry
        elif spec:
            blocks=tuple(BasicBlock(BlockId(fid, b.start-image_base), max(b.end-b.start, 1)) for b in spec.blocks)
            entry=next(b.id for b in blocks if b.id.rva==fid.rva)
        else:
            blocks=()
            entry=None
        functions.append(Function(fid, spec.name if spec else 'IDA call target without body metadata', blocks, entry))
        if fid in native_cfgs:cfgs.append(native_cfgs[fid])
        elif spec:
            mapped={b.id.rva+image_base:b.id for b in blocks}
            cfgs.append(ControlFlowGraph(fid, frozenset(mapped.values()), frozenset(
                FlowEdge(mapped[a], mapped[b], FlowKind.UNKNOWN, 'Original IDA CFG metadata; body not lifted') for a, b in spec.edges), entry))
    program=Program(binary, module.architecture, module.functions[0].abi, tuple(functions), tuple(sites.values()), image_base,
        Completeness.INCOMPLETE, ('Frontend function/call dependencies imported; unrequested bodies and external effects remain explicit',))
    cg=CallGraph(frozenset(declared), frozenset(edges), Completeness.INCOMPLETE,
                 'Frontend static dependencies plus explicit unknown/native-only calls; no historical target seed')
    return ProgramIndex(program, cg, tuple(cfgs), tuple(external), tuple(native_only))
