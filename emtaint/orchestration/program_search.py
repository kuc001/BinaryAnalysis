"""Batch graph refinement with dependency-driven reanalysis and explicit cap."""
from dataclasses import dataclass
import logging
import time
from emtaint.memory.engine import combine,over
from emtaint.debugging import log_event


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProgramSearchResult:
    results: tuple
    rounds: int
    invocations: int
    pending: tuple
    assessment: object


class CIRProgramSearch:
    def __init__(self,runtime,updater,analyze,max_rounds=3,order=None):
        if type(max_rounds) is not int or max_rounds<1:raise ValueError('Positive round budget required')
        self.runtime,self.updater,self.analyze,self.max_rounds=runtime,updater,analyze,max_rounds
        self.order=order

    def run(self,functions):
        started=time.monotonic()
        allowed=frozenset(functions);todo=set(allowed);results={};rounds=invocations=0;notes=[]
        log_event(LOGGER,'icall.search.started',level=logging.INFO,functions=len(allowed),
            max_rounds=self.max_rounds)
        while todo and rounds<self.max_rounds:
            rounds+=1;self.runtime.pending.difference_update(todo);batch=[]
            ordered=tuple(self.order(todo) if self.order else sorted(todo,key=lambda f:f.rva))
            log_event(LOGGER,'icall.search.round.started',level=logging.INFO,round=rounds,
                worklist=len(ordered),functions=[hex(function.rva) for function in ordered],
                pending_before=len(self.runtime.pending))
            for position,function in enumerate(ordered,1):
                # Analyze callback must construct a fresh current-scoped port.
                log_event(LOGGER,'icall.search.function.dispatched',function=hex(function.rva),
                    round=rounds,position=position,total=len(ordered))
                result=self.analyze(function);results[function]=result;batch.extend(result.targets);invocations+=1
            event_start=len(self.runtime.events)
            affected=self.updater.apply(batch)
            todo=set(self.runtime.pending)&allowed
            log_event(LOGGER,'icall.search.round.completed',level=logging.INFO,round=rounds,
                target_facts=len(batch),target_values=sum(len(fact.targets) for fact in batch),
                affected=len(affected),next_worklist=len(todo),new_runtime_events=self.runtime.events[event_start:],
                total_invocations=invocations)
        if todo:notes.append(over('Graph reanalysis round budget exhausted; pending callers retained',True))
        notes.extend(result.assessment for result in results.values())
        log_event(LOGGER,'icall.search.completed',level=logging.INFO,rounds=rounds,
            invocations=invocations,pending=len(self.runtime.pending),results=len(results),
            exhausted=bool(todo),wall_seconds=time.monotonic()-started)
        return ProgramSearchResult(tuple(sorted(results.items(),key=lambda pair:pair[0].rva)),rounds,invocations,
            tuple(sorted(self.runtime.pending,key=lambda f:f.rva)),combine(notes))
