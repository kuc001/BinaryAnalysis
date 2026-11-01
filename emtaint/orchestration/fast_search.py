"""Bounded CIR worklist with visible fixed-point/frontier and target evidence.

Legacy FastSearch's full summary/loop heuristics are not silently substituted.
This scheduler covers the transferred action subset and exposes the remainder.
"""
from collections import deque
from dataclasses import dataclass,replace
import time
from emtaint.core import BlockId,Completeness
from emtaint.core.contracts import ValueType,Assessment
from emtaint.ir.canonical import (BranchEffect,JumpEffect,ReturnEffect,CallEffect,IndirectTarget,DirectTarget,UnknownEffect)
from emtaint.memory.engine import combine,over
from emtaint.memory.policies import BudgetExceeded
from emtaint.analysis.framework.state import TargetFact


@dataclass(frozen=True)
class SearchResult:
    returns: tuple
    targets: tuple[TargetFact,...]
    pending: tuple
    assessment: Assessment
    steps: int
    visited_blocks: tuple


class CIRFastSearch:
    def __init__(self,function,flow,max_steps=10000,max_states=10000,image_base=0,extra_exits=None,input_assessment=Assessment.complete(),indirect_sites=None,wall_seconds=None):
        self.function,self.flow=function,flow
        self.max_steps,self.max_states,self.image_base=max_steps,max_states,image_base
        self.extra_exits=dict(extra_exits or {})
        self.input_assessment=input_assessment
        if min(max_steps,max_states)<=0:raise ValueError('Positive worklist budgets required')
        self.indirect_sites=dict(indirect_sites or {});self.wall_seconds=wall_seconds
        if wall_seconds is not None and wall_seconds<=0:raise ValueError('Positive wall budget required')

    def run(self,initial=None):
        blocks={b.id:b for b in self.function.blocks};p=self.flow.port
        start=initial or self.flow.initial()
        start=replace(start,assessment=combine((start.assessment,self.input_assessment)))
        queue=deque(((self.function.entry,start),));seen=set();returns=[];targets=[];notes=[];visited=set();steps=0
        started=time.monotonic()
        def enqueue(block,state):
            if block not in blocks:notes.append(over('Target block is outside lifted function',True));return
            queue.append((block,state))
        def guarded(state,guard):
            if p.concrete(guard) is True:return state
            guards=tuple(dict.fromkeys(state.guards+(guard,)))
            return replace(state,guards=guards)
        def resolve_target(state,operand,origin,site,kind):
            ref=self.flow.operand(state,operand,origin)
            values,top,assessments=p.candidates(ref)
            assessment=combine((state.assessment,*assessments))
            if top:assessment=combine((assessment,over('Unresolved target value has unknown remainder',True)))
            certainty='confirmed' if not top and len(values)==1 and not state.guards and assessment.status==Completeness.COMPLETE and assessment.precision.value=='exact' else 'may' if values else 'unknown'
            fact=TargetFact(site,values,kind,certainty,not top,state.memory,state.guards,origin,assessment,
                'CIR value and versioned byte-definition resolution; abstract feasibility is not a concrete witness')
            targets.append(fact);return values,top
        while queue:
            if steps>=self.max_steps or len(seen)>=self.max_states:
                notes.append(over('Worklist budget exhausted; pending frontier retained',True));break
            block_id,state=queue.popleft();identity=(block_id,state.memory,state.values,state.registers,state.addresses,state.guards,state.apgs,state.assessment,state.register_epoch)
            if identity in seen:continue
            seen.add(identity);visited.add(block_id);steps+=1
            block=blocks[block_id];terminated=False;forked=set()
            try:
                for effect in block.effects:
                    if self.wall_seconds is not None and time.monotonic()-started>self.wall_seconds:
                        raise TimeoutError('Function wall budget exhausted; unexecuted frontier retained')
                    origin=effect.origin
                    # Unknown side exits are forked at their exact IR origin,
                    # before later stores in the block can overwrite that path.
                    exits=() if origin in forked else self.extra_exits.get(origin,())
                    forked.add(origin)
                    for target in exits:
                        prior=self.flow.transfer(state,UnknownEffect(origin,'UnknownExit','Unknown guard; side-exit preserves prior register and memory definitions',(),(),True))
                        notes.append(prior.assessment)
                        enqueue(target,prior)
                    if isinstance(effect,BranchEffect):
                        ref=self.flow.operand(state,effect.condition,origin);value=p.concrete(ref)
                        if value is not False:enqueue(effect.if_true,guarded(state,ref))
                        if value is not True:
                            neg=p.operation('not',ValueType.boolean(),(ref,),origin)
                            enqueue(effect.if_false,guarded(state,neg))
                        terminated=True;break
                    if isinstance(effect,JumpEffect):
                        if isinstance(effect.target,BlockId):enqueue(effect.target,state)
                        else:
                            site=self.indirect_sites.get(origin)
                            values,top=resolve_target(state,effect.target,origin,site or origin,'icall' if site else 'switch')
                            if site is not None:
                                notes.append(over('Computed tail call has no validated callee summary',True));terminated=True;break
                            for value in values:
                                candidates=[bid for bid in blocks if bid.rva+self.image_base==(value&~1 if bid.mode=='thumb' else value)]
                                for bid in candidates:enqueue(bid,state)
                                if not candidates:notes.append(over('Computed target is outside known block boundaries',True))
                            if top:notes.append(over('Computed jump has unenumerated targets',True))
                        terminated=True;break
                    if isinstance(effect,ReturnEffect):
                        guard=self.flow.operand(state,effect.guard,origin);concrete=p.concrete(guard)
                        if concrete is not False:returns.append(guarded(state,guard))
                        if concrete is not True:notes.append(over('Conditional return has unspecified false-path control',True))
                        terminated=True;break
                    if isinstance(effect,CallEffect):
                        guard=self.flow.operand(state,effect.guard,origin)
                        if p.concrete(guard) is not False:
                            if isinstance(effect.target,IndirectTarget):resolve_target(state,effect.target.address,origin,effect.site,'icall')
                            elif isinstance(effect.target,DirectTarget):
                                address=effect.target.function.rva+self.image_base
                                targets.append(TargetFact(effect.site,(address,),'direct','confirmed',True,state.memory,state.guards,origin,state.assessment,'Static CIR direct target'))
                    state=self.flow.transfer(state,effect)
                    notes.append(state.assessment)
                if not terminated:notes.append(over('Block has no executed terminator',True))
            except BudgetExceeded as error:
                notes.append(error.assessment);queue.appendleft((block_id,state));break
            except TimeoutError as error:
                notes.append(over(str(error),True));queue.appendleft((block_id,state));break
            except (ValueError,KeyError,TypeError) as error:
                notes.append(over(type(error).__name__+': '+str(error),True));queue.appendleft((block_id,state));break
        if self.flow.diagnostics:notes.append(over('; '.join(dict.fromkeys(self.flow.diagnostics)),True))
        notes.extend(s.assessment for s in returns);notes.extend(f.assessment for f in targets)
        return SearchResult(tuple(returns),tuple(targets),tuple(queue),combine(notes),steps,tuple(sorted(visited,key=lambda x:x.token)))
