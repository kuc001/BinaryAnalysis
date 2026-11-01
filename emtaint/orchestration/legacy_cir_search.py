"""Python P6 legacy demand/summary scheduling through CIR and memory ports.

Loader bytes, source CFG edges and policy bounds are explicit frontend inputs.
This module does not access native IR, files, archived targets or global state.
"""
from dataclasses import dataclass
from emtaint.core import CallSiteId,BlockId,Completeness
from emtaint.core.contracts import Assessment
from emtaint.ir.canonical import CallEffect,IndirectTarget,JumpEffect,ReturnEffect,StoreEffect
from emtaint.memory.engine import combine,over
from emtaint.memory.policies import BudgetExceeded
from emtaint.analysis.framework.state import TargetFact
from emtaint.analysis.framework.summaries import compile_recipe
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.dataflow.legacy_demand import LegacyDemand,DemandBudget,DemandLimit
from emtaint.analysis.controlflow.legacy_tables import LegacyTableCollector


@dataclass(frozen=True)
class LegacyFunctionResult:
    targets:tuple
    pending:tuple
    assessment:object
    steps:int
    visited_blocks:tuple
    sites:tuple
    recipe:object
    snapshot:object
    metrics:object
    reference_recipes:tuple=()


class CIRLegacySearch:
    def __init__(self,function,origins,cfg,port,*,input_sites=(),image_base=0,
                 summaries=None,is_code=None,is_data=None,bounds=None,budget=DemandBudget(steps=250000,depth=500),
                 body_token='',make_recipe=True):
        self.function,self.origins,self.cfg,self.port=function,{o.id:o for o in origins},cfg,port
        self.input_sites=frozenset(input_sites);self.image_base=image_base
        self.summaries=summaries or {};self.bounds=bounds or {};self.budget=budget
        self.is_code=is_code or (lambda x:False);self.is_data=is_data or (lambda x:False)
        self.body_token=body_token;self.make_recipe=make_recipe

    def run(self):
        p=self.port;flow=CIRAccurateDataFlow(p);initial=legacy_entry(flow)
        demand=LegacyDemand(self.function,p,self.cfg,initial,budget=self.budget,summaries=self.summaries)
        facts=[];rows=[];pending=[];notes=[];recipe=None;reference_recipes=[]
        reachable={self.cfg.entry};todo=[self.cfg.entry]
        while todo:
            node=todo.pop()
            for target in self.cfg.successors(node):
                if target not in reachable:reachable.add(target);todo.append(target)
        for block in self.function.blocks:
            for effect in block.effects:
                origin=self.origins[effect.origin];point=origin.point
                site_address=None if point.instruction_rva is None else self.image_base+point.instruction_rva
                if site_address not in self.input_sites:continue
                if isinstance(effect,ReturnEffect):
                    rows.append({'site':site_address,'classification':'IDA annotation / CIR native return',
                                 'origin':effect.origin,'cfg_reachable':block.id in reachable,'targets':[]})
                    continue
                operand=effect.target.address if isinstance(effect,CallEffect) and isinstance(effect.target,IndirectTarget) else (
                    effect.target if isinstance(effect,JumpEffect) and not isinstance(effect.target,BlockId) else None)
                if operand is None:continue
                site=effect.site if isinstance(effect,CallEffect) else CallSiteId(point)
                row={'site':site_address,'origin':effect.origin,'cfg_reachable':block.id in reachable}
                collector=None
                try:
                    roots=demand.value(operand);collector=LegacyTableCollector(demand,self.is_code,self.is_data)
                    reference_recipes.append((site_address,compile_recipe(demand,roots,provenance=(self.body_token,'Same CIR demand roots for reference replay'))))
                    values=tuple(sorted({v for root in roots for v in collector.collect(root,maximum_address=self.bounds.get(site_address))}))
                    assessment=over('Legacy candidate collection over explicit initial loader bytes; runtime feasibility/memory remainder retained',True)
                    row.update(targets=list(values),expressions=[x.key for x in roots],
                               evidence=collector.evidence,unknown_remainder=True,
                               rule_ids=sorted(demand.rules),memory_version=initial.memory.key)
                except (DemandLimit,BudgetExceeded,RecursionError) as error:
                    values=tuple(sorted(collector.partial_targets)) if collector else ()
                    assessment=over(type(error).__name__+': '+str(error),True)
                    pending.append((site,assessment.diagnostics));row.update(targets=list(values),error=str(error),unknown_remainder=True)
                facts.append(TargetFact(site,values,'icall','may' if values else 'unknown',False,initial.memory,(),
                    effect.origin,assessment,'Legacy CIR use/def, callsite recipe substitution and MemoryQueryPort loader-table candidates'))
                notes.append(assessment);rows.append(row)
        if self.make_recipe:
            roots=[]
            try:
                for block in self.function.blocks:
                    for effect in block.effects:
                        if isinstance(effect,ReturnEffect):
                            for value in effect.values:roots.extend(demand.value(value))
                stores=[]
                for block in self.function.blocks:
                    for effect in block.effects:
                        if isinstance(effect,StoreEffect):
                            binding=demand.local_address(effect.address)
                            if binding is not None and binding[0].region=='stack':continue
                            stores.append((effect,demand.value(effect.address),demand.value(effect.value)))
                if roots or stores:recipe=compile_recipe(demand,roots,stores=stores,provenance=(self.body_token,'Actual CIR callee use/def/return recipe'))
            except (DemandLimit,BudgetExceeded,RecursionError) as error:
                notes.append(over('Procedure recipe incomplete: '+str(error),True))
                pending.append(('recipe',str(error)))
        if demand.notes:notes.append(over('; '.join(sorted(set(demand.notes))),True))
        if len(rows)<len(self.input_sites):
            missing=self.input_sites-{row['site'] for row in rows}
            pending.extend(('missing-site',site) for site in sorted(missing))
            notes.append(over('Input sites lack a CIR call/return terminal',True))
        snapshot=p.engine.snapshot()
        notes.append(snapshot.assessment)
        if self.cfg.status!=Completeness.COMPLETE:notes.append(over('Source CFG coverage/guard feasibility remains incomplete',True))
        return LegacyFunctionResult(tuple(facts),tuple(pending),combine(notes),demand.steps,
            tuple(sorted(reachable,key=lambda x:x.token)),tuple(rows),recipe,snapshot,p.metrics(),tuple(reference_recipes))


def callee_first(functions,graph):
    """Deterministic dependency postorder; cycles are left for reanalysis."""
    functions=frozenset(functions);children={f:set() for f in functions}
    for edge in graph.edges:
        if edge.site.function in functions and edge.target in functions:children[edge.site.function].add(edge.target)
    done=set();visiting=set();result=[]
    for root in sorted(functions,key=lambda f:f.rva):
        pending=[(root,False)]
        while pending:
            current,ready=pending.pop()
            if current in done:continue
            if ready:
                visiting.discard(current);done.add(current);result.append(current);continue
            if current in visiting:continue
            visiting.add(current);pending.append((current,True))
            pending.extend((c,False) for c in sorted(children[current],key=lambda f:f.rva,reverse=True) if c not in visiting and c not in done)
    return tuple(result)


@dataclass(frozen=True)
class EngineAttempt:
    active_engine:str
    primary:object
    result:object
    reason:str=''


def run_with_legacy_fallback(apg,legacy):
    """A real supplied legacy runner, never an archived-output substitute."""
    attempt=None
    try:
        result=apg()
        attempt=result
        if result.pending:raise DemandLimit('APG attempt has unresolved execution frontier')
        return EngineAttempt('apg',result,result)
    except (DemandLimit,BudgetExceeded,RecursionError) as error:
        if legacy is None:raise RuntimeError('Legacy fallback runner is unavailable') from error
        return EngineAttempt('legacy',attempt,legacy(),str(error))
