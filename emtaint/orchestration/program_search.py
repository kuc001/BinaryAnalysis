"""Batch graph refinement with dependency-driven reanalysis and explicit cap."""
from dataclasses import dataclass
from emtaint.memory.engine import combine,over


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
        allowed=frozenset(functions);todo=set(allowed);results={};rounds=invocations=0;notes=[]
        while todo and rounds<self.max_rounds:
            rounds+=1;self.runtime.pending.difference_update(todo);batch=[]
            for function in (self.order(todo) if self.order else sorted(todo,key=lambda f:f.rva)):
                # Analyze callback must construct a fresh current-scoped port.
                result=self.analyze(function);results[function]=result;batch.extend(result.targets);invocations+=1
            self.updater.apply(batch)
            todo=set(self.runtime.pending)&allowed
        if todo:notes.append(over('Graph reanalysis round budget exhausted; pending callers retained',True))
        notes.extend(result.assessment for result in results.values())
        return ProgramSearchResult(tuple(sorted(results.items(),key=lambda pair:pair[0].rva)),rounds,invocations,
            tuple(sorted(self.runtime.pending,key=lambda f:f.rva)),combine(notes))
