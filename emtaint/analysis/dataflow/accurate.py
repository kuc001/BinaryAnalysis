"""P6 CIR transfer subset of legacy AccurateDataFlow action families.

This is not the full old trace engine. Unsupported families retain explicit
unknown/havoc; default legacy selection is not replaced by this experiment.
"""
from dataclasses import dataclass,replace
from emtaint.core.contracts import ValueType,TypeKind,Assessment,Constant
from emtaint.core import Completeness
from emtaint.ir.canonical import (Compute,ReadRegister,WriteRegister,RegisterWritePolicy,
    LoadEffect,StoreEffect,UnknownEffect,HavocEffect,CallEffect,DirectTarget)
from emtaint.memory import SymbolicOp
from emtaint.memory.engine import combine,over
from emtaint.analysis.framework.state import FlowState


@dataclass(frozen=True)
class ProcedureSummary:
    argument_index: int | None
    write_regions: tuple[str,...]
    proof: str

    @classmethod
    def identity(cls,index,proof):
        if type(index) is not int or index<0 or not proof:raise ValueError('Summary needs argument/proof')
        return cls(index,(),proof)


class CIRAccurateDataFlow:
    def __init__(self,port,summaries=None):
        self.port=port;self.summaries=dict(summaries or {});self.diagnostics=[]

    def initial(self):
        self.port.validate_current()
        return FlowState(self.port.initial,self.port.scope.context,addresses=tuple(self.port.seed_addresses.items()),assessment=Assessment.complete())

    def operand(self,state,value,origin):
        if isinstance(value,Constant):return self.port.constant(value.value,value.type,origin)
        values=dict(state.values)
        if value.id not in values:
            self.diagnostics.append('Undefined CIR value: '+value.id)
            return self.port.unknown(value.type,origin,'Undefined CIR value '+value.id)
        return values[value.id]

    def as_bv(self,value,origin):
        type_=self.port.type_of(value)
        if type_.kind!=TypeKind.POINTER:return value
        return self.port.operation(SymbolicOp.SUB,ValueType.bv(type_.bits),
            (value,self.port.constant(0,type_,origin)),origin)

    def as_type(self,value,type_,origin):
        if self.port.type_of(value)==type_:return value
        if type_.kind==TypeKind.POINTER and self.port.type_of(value)==ValueType.bv(type_.bits):
            return self.port.operation(SymbolicOp.ADD,type_,(self.port.constant(0,type_,origin),value),origin)
        raise ValueError('CIR transfer value sort mismatch')

    def transfer(self,state,effect):
        self.port.validate_current()
        p=self.port;origin=effect.origin;values=dict(state.values);regs=dict(state.registers);addresses=dict(state.addresses)
        state=replace(state,point=p.point(origin))
        assessment=state.assessment;memory=state.memory;register_epoch=state.register_epoch
        op=lambda operand:self.operand(state,operand,origin)
        truth=lambda: p.constant(True,ValueType.boolean(),origin)
        def update_value(name,ref,binding=None):
            values[name]=ref;addresses.pop(name,None)
            if binding is not None:addresses[name]=binding
        if isinstance(effect,Compute):
            args=tuple(op(x) for x in effect.args)
            binding=None
            first=addresses.get(effect.args[0].id) if hasattr(effect.args[0],'id') else None
            if effect.op.value=='copy':binding=first
            elif effect.op.value in ('add','sub'):
                offset=p.concrete(args[1])
                if first is not None and offset is not None:
                    root,base=first;binding=(root,base+(offset if effect.op.value=='add' else -offset))
                elif effect.op.value=='add' and p.concrete(args[0])==0 and hasattr(effect.args[1],'id'):
                    binding=addresses.get(effect.args[1].id)
            update_value(effect.result.id,p.operation(effect.op,effect.result.type,args,origin,effect.params),binding)
        elif isinstance(effect,ReadRegister):
            source=effect.source;full=regs.get(source.register)
            if full is None:full=p.symbol('register:'+source.register+':epoch:'+str(register_epoch),ValueType.bv(source.register_width_bits),origin)
            value=full
            if source.bit_offset or source.width_bits!=source.register_width_bits:
                value=p.operation(SymbolicOp.EXTRACT,ValueType.bv(source.width_bits),(full,),origin,
                                  (source.bit_offset+source.width_bits-1,source.bit_offset))
            binding=addresses.get('reg:'+source.register) if source.bit_offset==0 and source.width_bits==source.register_width_bits else None
            update_value(effect.result.id,self.as_type(value,effect.result.type,origin),binding)
        elif isinstance(effect,WriteRegister):
            guard=op(effect.guard)
            if p.concrete(guard) is False:return state
            target=effect.target;width=target.register_width_bits
            old=regs.get(target.register) or p.symbol('register:'+target.register+':epoch:'+str(register_epoch),ValueType.bv(width),origin)
            value=self.as_bv(op(effect.value),origin)
            if effect.policy==RegisterWritePolicy.ZERO_UPPER:
                if width>target.width_bits:value=p.operation(SymbolicOp.ZERO_EXTEND,ValueType.bv(width),(value,),origin,(width-target.width_bits,))
            elif effect.policy==RegisterWritePolicy.PRESERVE_OTHERS:
                pieces=[]
                high=target.bit_offset+target.width_bits
                if high<width:pieces.append(p.operation(SymbolicOp.EXTRACT,ValueType.bv(width-high),(old,),origin,(width-1,high)))
                pieces.append(value)
                if target.bit_offset:pieces.append(p.operation(SymbolicOp.EXTRACT,ValueType.bv(target.bit_offset),(old,),origin,(target.bit_offset-1,0)))
                if len(pieces)>1:value=p.operation(SymbolicOp.CONCAT,ValueType.bv(width),tuple(pieces),origin)
            if p.concrete(guard) is not True:value=p.operation(SymbolicOp.IF,ValueType.bv(width),(guard,value,old),origin)
            regs[target.register]=value;addresses.pop('reg:'+target.register,None)
            if effect.policy==RegisterWritePolicy.FULL and p.concrete(guard) is True and hasattr(effect.value,'id'):
                binding=addresses.get(effect.value.id)
                if binding is not None:addresses['reg:'+target.register]=binding
        elif isinstance(effect,(LoadEffect,StoreEffect)):
            guard=op(effect.guard)
            if p.concrete(guard) is False:return state
            loc=p.location(effect.address,addresses,values,effect.width_bits,effect.endian,origin)
            if isinstance(effect,StoreEffect):
                result=p.write(memory,loc,op(effect.value),guard,origin);memory=result.state
            else:
                result=p.read(memory,loc,guard,origin)
                ref=self.as_type(result.value,effect.result.type,origin)
                if p.concrete(guard) is not True:
                    old=values.get(effect.result.id) or p.unknown(effect.result.type,origin,'Unexecuted load has no prior value')
                    ref=p.operation(SymbolicOp.IF,effect.result.type,(guard,ref,old),origin)
                update_value(effect.result.id,ref)
            assessment=combine((assessment,result.assessment))
        elif isinstance(effect,UnknownEffect):
            if effect.may_write_registers:register_epoch+=1
            if effect.may_write_regions:memory=p.havoc(memory,effect.may_write_regions,effect.reason,origin)
            if '*' in effect.may_write_registers:regs.clear();addresses={k:v for k,v in addresses.items() if not k.startswith('reg:')}
            else:
                for name in effect.may_write_registers:regs.pop(name,None);addresses.pop('reg:'+name,None)
            assessment=combine((assessment,over(effect.source_opcode+': '+effect.reason,True)))
        elif isinstance(effect,(CallEffect,HavocEffect)):
            guard=op(effect.guard)
            if p.concrete(guard) is False:return state
            summary=self.summaries.get(effect.target.function) if isinstance(effect,CallEffect) and isinstance(effect.target,DirectTarget) else None
            regions=summary.write_regions if summary else effect.footprint.write_regions if isinstance(effect,CallEffect) else effect.regions
            if regions:memory=p.havoc(memory,regions,'Call/explicit side effects',origin,guard)
            if isinstance(effect,CallEffect):
                for result in effect.results:
                    if summary and summary.argument_index is not None and summary.argument_index<len(effect.arguments):
                        value=self.as_type(op(effect.arguments[summary.argument_index]),result.type,origin)
                    else:value=p.unknown(result.type,origin,'Call result without validated summary')
                    if summary is not None and (summary.argument_index is None or summary.argument_index>=len(effect.arguments)):
                        assessment=combine((assessment,over('Summary argument is unavailable',True)))
                    if p.concrete(guard) is not True:
                        prior=values.get(result.id) or p.unknown(result.type,origin,'Unexecuted call result')
                        value=p.operation(SymbolicOp.IF,result.type,(guard,value,prior),origin)
                    update_value(result.id,value)
                clobbers=effect.footprint.clobbered_registers
            else:clobbers=effect.registers
            if clobbers:register_epoch+=1
            if '*' in clobbers:regs.clear();addresses={k:v for k,v in addresses.items() if not k.startswith('reg:')}
            else:
                for name in clobbers:regs.pop(name,None);addresses.pop('reg:'+name,None)
            if summary is None:assessment=combine((assessment,over('Call/IR side effect lacks complete summary',True)))
        else:raise TypeError('Control effect must be handled by the worklist: '+type(effect).__name__)
        return replace(state,memory=memory,values=tuple(sorted(values.items())),registers=tuple(sorted(regs.items())),
            addresses=tuple(sorted(addresses.items())),assessment=assessment,register_epoch=register_epoch)
