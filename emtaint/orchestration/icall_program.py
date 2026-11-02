"""Production P7 CLI reuse of the characterized P6 CIR iCall pass."""
import logging
import time
from emtaint.core import ContextId
from emtaint.core.contracts import AnalysisScope,SemanticBudgets
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.compat.legacy_icall_policy import legacy_maximum_address
from emtaint.analysis.framework.runtime import AnalysisRuntime
from emtaint.analysis.controlflow.targets import TargetGraphUpdater
from emtaint.orchestration.legacy_cir_search import CIRLegacySearch,callee_first
from emtaint.orchestration.program_search import CIRProgramSearch
from emtaint.debugging import log_event,progress_heartbeat


LOGGER = logging.getLogger(__name__)


def recover_icalls(module,index,segments,sections,input_sites,body_hashes,*,max_rounds=4):
    started=time.monotonic()
    base=index.program.image_base;functions={f.function_id:f for f in module.functions}
    origins={f:tuple(o for o in module.origin_map if o.point.function==f) for f in functions}
    runtime=AnalysisRuntime(index.program);runtime.session.replace_cg(index.cg)
    for cfg in index.cfgs:runtime.session.replace_cfg(cfg)
    summary_functions=set(functions)-{f for f in functions if any(caller==f.rva+base for caller,site in input_sites)}
    log_event(LOGGER,'icall.runtime.ready',level=logging.INFO,functions=len(functions),
        input_sites=len(input_sites),summary_functions=len(summary_functions),max_rounds=max_rounds,
        initial_cg_edges=len(index.cg.edges),initial_cfgs=len(index.cfgs))
    text=sections['.text'];is_code=lambda v:text[0]<=v<=text[1]
    is_data=lambda v:any(a<=v<=b for name,(a,b) in sections.items() if name in ('.data','.rodata','.bss','.got','.init_array'))
    invocations=[]
    def analyze(fid):
        function_started=time.monotonic();address=fid.rva+base
        context=ContextId();scope=AnalysisScope.from_session(runtime.session,fid,context)
        engine=ImageMemoryEngine(scope,module.architecture,origins[fid],segments,
            SemanticBudgets(sse_nodes=200000,worklist_iterations=2000000),initial_policy='legacy-loader-snapshot')
        port=MemoryRuntimePort(engine);runtime.bind_port(port,fid,context)
        recipes={f:runtime.recipe_get(f,context) for f in functions if runtime.recipe_get(f,context) is not None}
        sites=[s for caller,s in input_sites if caller==fid.rva+base]
        log_event(LOGGER,'icall.analysis.started',function=hex(address),sites=len(sites),
            available_recipes=len(recipes),make_recipe=fid in summary_functions,
            function_epoch=runtime.epochs[fid],cg_revision=runtime.session.stamp.state_revision)
        search=CIRLegacySearch(functions[fid],origins[fid],runtime.session.cfg(fid),port,input_sites=sites,
            image_base=base,summaries=recipes,is_code=is_code,is_data=is_data,
            bounds={s:legacy_maximum_address(module.binary_sha256,s) for s in sites},
            body_token=body_hashes[fid],make_recipe=fid in summary_functions)
        with progress_heartbeat(LOGGER,'icall.analysis.heartbeat',function=hex(address),sites=len(sites),
                function_epoch=runtime.epochs[fid]):
            result=search.run()
        recipe_affected=frozenset()
        if result.recipe is not None:recipe_affected=runtime.recipe_put(fid,context,result.recipe)
        invocations.append({'function':fid.rva+base,'steps':result.steps,'metrics':result.metrics,'pending':len(result.pending)})
        log_event(LOGGER,'icall.analysis.completed',function=hex(address),steps=result.steps,
            sites=len(result.sites),target_facts=len(result.targets),
            target_values=sum(len(fact.targets) for fact in result.targets),pending=len(result.pending),
            recipe_nodes=0 if result.recipe is None else len(result.recipe.nodes),
            recipe_returns=0 if result.recipe is None else len(result.recipe.returns),
            recipe_invalidated=len(recipe_affected),metrics=result.metrics,
            wall_seconds=time.monotonic()-function_started)
        return result
    updater=TargetGraphUpdater(runtime,module.origin_map)
    log_event(LOGGER,'icall.fixed_point.started',level=logging.INFO,functions=len(functions),max_rounds=max_rounds)
    result=CIRProgramSearch(runtime,updater,analyze,max_rounds=max_rounds,
                           order=lambda todo:callee_first(todo,runtime.session.cg)).run(functions)
    log_event(LOGGER,'icall.fixed_point.completed',level=logging.INFO,rounds=result.rounds,
        invocations=result.invocations,pending=len(result.pending),runtime_events=len(runtime.events),
        unmapped_targets=len(updater.unmapped),final_cg_edges=len(runtime.session.cg.edges),
        wall_seconds=time.monotonic()-started)
    return runtime,result,tuple(invocations)
