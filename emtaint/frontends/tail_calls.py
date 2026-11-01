"""Verified native tail branches plus IDA/PLT identity, lowered to CIR ABI calls.

The original immutable acquisition remains intact. Metadata alone cannot turn
an unresolved jump into a call. Added effects retain a separate origin and
the original native terminal's identity in the transformation receipt.
"""
from dataclasses import replace
from emtaint.core import CallSiteId,FunctionId
from emtaint.core.contracts import ValueRef,ValueType,Constant
from emtaint.ir.canonical import (JumpEffect,CallEffect,ReturnEffect,ReadRegister,
    RegisterSlice,CallFootprint,DirectTarget,ExternalTarget)
from emtaint.analysis.controlflow.local_constants import local_terminal_constants


def complete_tail_calls(module,cfg,calls,image_base,plt):
    function=module.functions[0];origins={o.id:o for o in module.origin_map}
    hints={row['instruction']:row for row in calls};constants=local_terminal_constants(function,image_base)
    blocks=[];values=list(function.values);added=[];receipts=[];tails=set()
    truth=Constant(True,ValueType.boolean());type_=ValueType.bv(module.architecture.pointer_bits)
    for block in function.blocks:
        effects=list(block.effects)
        if effects and isinstance(effects[-1],JumpEffect):
            native=effects[-1];origin=origins[native.origin];instruction=origin.point.instruction_rva
            hint=hints.get(None if instruction is None else instruction+image_base)
            if hint:
                expected=hint['target'] if type(hint['target']) is int else plt.get(hint['target'])
                targets=constants.get(native.origin,())
                if expected is not None and targets==(expected,):
                    abi=function.abi
                    if not abi.argument_registers or not abi.return_registers:
                        raise ValueError('A verified tail call still requires a declared ABI')
                    translated=replace(origin,id=origin.id+':tail',point=replace(origin.point,statement=None),
                        source_opcode=origin.source_opcode+':verified-tail-call-ABI')
                    added.append(translated);effects.pop();arguments=[]
                    for i,name in enumerate(abi.argument_registers):
                        value=ValueRef(translated.id+':arg'+str(i),type_);values.append(value);arguments.append(value)
                        effects.append(ReadRegister(translated.id,value,RegisterSlice(name,0,type_.bits,type_.bits)))
                    results=tuple(ValueRef(translated.id+':ret'+str(i),type_) for i in range(len(abi.return_registers)))
                    values.extend(results)
                    target=(DirectTarget(FunctionId(function.function_id.binary,expected-image_base)) if type(hint['target']) is int else ExternalTarget(hint['target']))
                    footprint=CallFootprint(clobbered_registers=abi.caller_saved,unknown=False,
                        reason='Verified tail call uses declared ABI; memory effects still unknown')
                    effects.extend((CallEffect(translated.id,CallSiteId(translated.point),target,tuple(arguments),results,abi,truth,footprint),
                                    ReturnEffect(translated.id,results,truth)))
                    tails.add(block.id)
                    receipts.append({'instruction':instruction+image_base,'target':expected,'identity':hint['target'],
                        'native_origin':native.origin,'derived_origin':translated.id,
                        'proof':'Singleton native block-local PC target equals actual PLT/IDA call target; tail ABI projection'})
        blocks.append(replace(block,effects=tuple(effects)))
    if not receipts:return module,cfg,()
    function=replace(function,values=tuple(values),blocks=tuple(blocks))
    module=replace(module,functions=(function,),origin_map=module.origin_map+tuple(added))
    cfg=replace(cfg,edges=frozenset(edge for edge in cfg.edges if edge.source not in tails),exits=cfg.exits|tails)
    return module,cfg,tuple(receipts)
