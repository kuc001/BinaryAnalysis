"""Characterized SecurityCheck policy, separated from flow/solver evidence.

These are the original heuristic candidate decisions, never confirmations of
concrete exploitability. Native trace objects and global weak tables stay out.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class WeakEvidence:
    site:int
    function:int
    name:str
    kind:str
    source:int
    stack_address:int|None=None
    memory_size:int|None=None
    constraints:tuple=()
    constraint_ids:tuple=()
    inter_functions:tuple=()
    indirect_depth:int|None=None
    propagation_level:int|None=None
    loop_count:int|None=None
    flow_evidence:tuple=()
    callsite_path:tuple=()
    path_scope:str='Unmeasured; no concrete execution witness'


@dataclass(frozen=True)
class PolicyDecision:
    evidence:WeakEvidence
    candidate:bool
    offset:int|None
    reason:str
    confirmed:bool=False
    classification:str='legacy-heuristic'


@dataclass(frozen=True)
class SourceHandleEvidence:
    sources:tuple
    flag:int
    constraint_type:int
    contains_open_marker:bool=False


def fake_file_sources(handles):
    """SecurityCheck.get_file_open_taint_sources, including socket override."""
    files=set();sockets=set()
    for handle in handles:
        if not handle.flag&0x4000 or not handle.sources:continue
        if handle.constraint_type==0x11:sockets.update(handle.sources)
        elif handle.constraint_type==0x8 or handle.contains_open_marker:files.update(handle.sources)
    return frozenset(files-sockets)


class LegacySecurityPolicy:
    def __init__(self,*,max_length=0,fake_sources=()):
        self.max_length=max_length;self.fake_sources=frozenset(fake_sources)

    @staticmethod
    def guess_max_length(values):
        return max((v for v in values if type(v) is int and v>=0x2000),default=0)

    def classify(self,evidence):
        if evidence.source in self.fake_sources:return PolicyDecision(evidence,False,None,'Legacy file-handle source filtered')
        if evidence.kind=='command':return PolicyDecision(evidence,True,None,'Legacy command weak evidence reaches sink; feasibility not proved')
        if evidence.kind not in ('copy','copy_length'):return PolicyDecision(evidence,False,None,'Unsupported legacy weak category')
        constraints=evidence.constraints
        if any(type(c) is str and c!='Y' for c in constraints):
            return PolicyDecision(evidence,False,None,'Legacy symbolic constraint filter; not a safety proof')
        offset=(0x7fffffff-evidence.stack_address if evidence.stack_address is not None else evidence.memory_size or None)
        if offset is None or not 0<=offset<=0xfffff:
            return PolicyDecision(evidence,False,offset,'Legacy destination extent unavailable/outside heuristic range')
        concrete=[c for c in constraints if type(c) is int and c not in (0,1)]
        minimum=min(concrete) if concrete else None
        # A concrete value is only an excluding upper bound when every
        # inherited length recipe was resolved.  Otherwise it describes one
        # completed alternative, while ``constraint_ids`` records an omitted
        # frontier.  Treating that partial minimum as exhaustive would turn
        # Incomplete into a clean result.  Preserve a conservative MAY; this
        # remains legacy-heuristic evidence and is never a confirmation.
        incomplete_bound=minimum is not None and bool(evidence.constraint_ids)
        candidate=(incomplete_bound or
            (minimum is None and len(evidence.constraint_ids)==0) or
            (minimum is None and self.max_length and self.max_length>=offset) or
            (minimum is None and self.max_length==0) or
            (minimum is not None and minimum>=offset))
        return PolicyDecision(evidence,bool(candidate),offset,
            ('Incomplete length frontier; conservative MAY, not a safety or exploitability proof'
                if incomplete_bound and minimum<offset else
             'Legacy length/extent candidate; path and constraints require independent validation') if candidate else
            'Legacy numeric bound excludes candidate; not an unconditional sanitizer')
