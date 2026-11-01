"""Production P7 CLI reuse of the characterized P6 CIR iCall pass."""
from emtaint.core import ContextId
from emtaint.core.contracts import AnalysisScope,SemanticBudgets
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.compat.legacy_icall_policy import legacy_maximum_address
from emtaint.analysis.framework.runtime import AnalysisRuntime
from emtaint.analysis.controlflow.targets import TargetGraphUpdater
from emtaint.orchestration.legacy_cir_search import CIRLegacySearch,callee_first
from emtaint.orchestration.program_search import CIRProgramSearch


def recover_icalls(module,index,segments,sections,input_sites,body_hashes,*,max_rounds=4):
    base=index.program.image_base;functions={f.function_id:f for f in module.functions}
    origins={f:tuple(o for o in module.origin_map if o.point.function==f) for f in functions}
    runtime=AnalysisRuntime(index.program);runtime.session.replace_cg(index.cg)
    for cfg in index.cfgs:runtime.session.replace_cfg(cfg)
    summary_functions=set(functions)-{f for f in functions if any(caller==f.rva+base for caller,site in input_sites)}
    text=sections['.text'];is_code=lambda v:text[0]<=v<=text[1]
    is_data=lambda v:any(a<=v<=b for name,(a,b) in sections.items() if name in ('.data','.rodata','.bss','.got','.init_array'))
    invocations=[]
    def analyze(fid):
        context=ContextId();scope=AnalysisScope.from_session(runtime.session,fid,context)
        engine=ImageMemoryEngine(scope,module.architecture,origins[fid],segments,
            SemanticBudgets(sse_nodes=200000,worklist_iterations=2000000),initial_policy='legacy-loader-snapshot')
        port=MemoryRuntimePort(engine);runtime.bind_port(port,fid,context)
        recipes={f:runtime.recipe_get(f,context) for f in functions if runtime.recipe_get(f,context) is not None}
        sites=[s for caller,s in input_sites if caller==fid.rva+base]
        result=CIRLegacySearch(functions[fid],origins[fid],runtime.session.cfg(fid),port,input_sites=sites,
            image_base=base,summaries=recipes,is_code=is_code,is_data=is_data,
            bounds={s:legacy_maximum_address(module.binary_sha256,s) for s in sites},
            body_token=body_hashes[fid],make_recipe=fid in summary_functions).run()
        if result.recipe is not None:runtime.recipe_put(fid,context,result.recipe)
        invocations.append({'function':fid.rva+base,'steps':result.steps,'metrics':result.metrics,'pending':len(result.pending)})
        return result
    updater=TargetGraphUpdater(runtime,module.origin_map)
    result=CIRProgramSearch(runtime,updater,analyze,max_rounds=max_rounds,
                           order=lambda todo:callee_first(todo,runtime.session.cg)).run(functions)
    return runtime,result,tuple(invocations)
