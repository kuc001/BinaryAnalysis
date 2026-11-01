"""Commit may/confirmed CIR target evidence; never import Golden as new facts."""
from emtaint.graph import CallEdge,TargetKind,FlowEdge,FlowKind


class TargetGraphUpdater:
    def __init__(self,runtime,origins):
        self.runtime=runtime;self.origins={o.id:o for o in origins};self.unmapped=[]

    def apply(self,facts):
        session=self.runtime.session;program=session.program;call_edges=set();cfgs={};affected=set();sites=set()
        for fact in facts:
            if fact.kind in ('icall','direct'):
                sites.add(fact.site)
                for value in fact.targets:
                    try:target=program.function_at(value)
                    except ValueError:target=None
                    if target is None:self.unmapped.append((fact.origin,value,'Undeclared callee'));continue
                    certainty=TargetKind.CONFIRMED if fact.certainty=='confirmed' else TargetKind.MAY
                    call_edges.add(CallEdge(fact.site,target.id,certainty,self.runtime.INFERRED_PREFIX+fact.evidence))
            elif fact.kind=='switch':
                origin=self.origins[fact.origin];source=origin.point.block
                cfg=cfgs.get(source.function,session.cfg(source.function))
                for value in fact.targets:
                    matches=[b for b in cfg.nodes if program.absolute_address(b.rva)==(value&~1 if b.mode=='thumb' else value)]
                    if not matches:self.unmapped.append((fact.origin,value,'Undeclared switch block'))
                    for target in matches:cfg=cfg.with_edge(FlowEdge(source,target,FlowKind.SWITCH,'P6 abstract computed-target candidate'))
                cfgs[source.function]=cfg
        if sites:affected.update(self.runtime.replace_inferred_call_edges(sites,call_edges))
        for cfg in cfgs.values():affected.update(self.runtime.replace_cfg(cfg))
        return frozenset(affected)
