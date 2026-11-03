"""Replay one frozen CIR/loader bundle on the full graph, then compare reference."""
import argparse
from dataclasses import asdict,replace
import hashlib
import json
from pathlib import Path
import sys
import time
import traceback
from enum import Enum

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET));sys.path.insert(0,str(TARGET/'tests'))
from p1_runtime import ProbeWriteGuard
from p6_memory_archive import archive_memory
from emtaint.frontends.saved_cir import load_saved_cir
from emtaint.frontends.inputs import read_ida_cfg
from emtaint.frontends.program_index import build_program_index
from emtaint.core import ContextId,Completeness
from emtaint.core.contracts import AnalysisScope,SemanticBudgets
from emtaint.graph import ControlFlowGraph,FlowEdge,FlowKind
from emtaint.ir.canonical import ReturnEffect
from emtaint.ir.canonical.wire import dumps
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.compat.legacy_icall_policy import legacy_maximum_address
from emtaint.analysis.framework.runtime import AnalysisRuntime
from emtaint.analysis.framework.runtime import StaleAnalysis
from emtaint.analysis.framework.summaries import SummaryNode
from emtaint.core.contracts import ValueType
from emtaint.analysis.controlflow.local_constants import local_constant_edges,ida_metadata_edges
from emtaint.analysis.controlflow.targets import TargetGraphUpdater
from emtaint.orchestration.legacy_cir_search import CIRLegacySearch,callee_first
from emtaint.orchestration.program_search import CIRProgramSearch


def write(path,value):
    with path.open('x',encoding='utf8') as stream:json.dump(value,stream,indent=2,default=lambda x:x.value if isinstance(x,Enum) else str(x))

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--cir-folder',type=Path,required=True);parser.add_argument('--loader',type=Path,required=True)
    parser.add_argument('--legacy-cg',type=Path,required=True);parser.add_argument('--max-rounds',type=int,default=4)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p6-work');folder.mkdir(exist_ok=False)
    guard=ProbeWriteGuard([folder]).install();started=time.monotonic();report={};invocations=[]
    source_files=[p for root in ('emtaint','scripts') for p in (TARGET/root).rglob('*.py')]
    source_hashes={p.relative_to(TARGET).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in source_files}
    try:
        module,frontend,body_hashes=load_saved_cir(args.cir_folder)
        base=frontend['metadata']['image_base'];functions={f.function_id:f for f in module.functions}
        local_origins={fid:tuple(o for o in module.origin_map if o.point.function==fid) for fid in functions}
        loader=json.loads((args.loader/'loader.json').read_text(encoding='utf8'))
        if not loader['passed'] or loader['binary_sha256']!=module.binary_sha256:raise ValueError('Loader/CIR binary mismatch')
        segments=tuple((s['base'],(args.loader/s['file']).read_bytes(),s['memsz'],s['flags']) for s in loader['segments'])
        if any(hashlib.sha256(data).hexdigest()!=row['sha256'] for (_,data,_,_),row in zip(segments,loader['segments'])):raise ValueError('Loader segment hash mismatch')
        sections=loader['sections'];text=sections['.text']
        is_code=lambda value:text[0]<=value<=text[1]
        is_data=lambda value:any(a<=value<=b for name,(a,b) in sections.items() if name in ('.data','.rodata','.bss','.got','.init_array'))
        data=TARGET.parent/'EmTaint/data/ida_data/rv130_1_0_3_44'
        info=json.loads((data/'httpd_block_info.json').read_text(encoding='utf8'))
        input_sites=sorted((int(f,16),row[0]) for f,blocks in info.items() for rows in blocks.values() for row in rows if row[-1]=='iCall')
        native_cfgs=[]
        for row in frontend['cfgs']:
            fid=next(f for f in functions if f.rva==row['function_rva']);function=functions[fid]
            blocks={b.id.token:b.id for b in function.blocks}
            cfg=ControlFlowGraph(fid,frozenset(blocks.values()),frozenset(FlowEdge(blocks[a],blocks[b],FlowKind(k),label) for a,b,k,label in row['edges']),function.entry)
            cfg=local_constant_edges(function,cfg,base)
            cfg=ida_metadata_edges(function,cfg,frontend['block_mappings'],frontend['metadata']['ida_edges'].get(hex(fid.rva+base),()),base)
            native_cfgs.append(cfg)
        index=build_program_index(module,read_ida_cfg(data/'httpd_cfg.json'),base,input_sites=input_sites,native_cfgs=native_cfgs)
        runtime=AnalysisRuntime(index.program)
        # Initial import owns no live handles/caches; it needs no reanalysis.
        runtime.session.replace_cg(index.cg)
        for cfg in index.cfgs:runtime.session.replace_cfg(cfg)
        summaries=set(functions)-{f for f in functions if any(caller==f.rva+base for caller,site in input_sites)}
        current_ports={};passes={};archive_enabled=True
        def analyze(fid):
            context=ContextId();scope=AnalysisScope.from_session(runtime.session,fid,context)
            engine=ImageMemoryEngine(scope,module.architecture,local_origins[fid],segments,
                SemanticBudgets(sse_nodes=200000,worklist_iterations=2000000),initial_policy='legacy-loader-snapshot')
            port=MemoryRuntimePort(engine);runtime.bind_port(port,fid,context);current_ports[fid]=port
            recipes={f:runtime.recipe_get(f,context) for f in functions if runtime.recipe_get(f,context) is not None}
            sites=[s for caller,s in input_sites if caller==fid.rva+base]
            bounds={s:legacy_maximum_address(module.binary_sha256,s) for s in sites}
            tick=time.monotonic()
            result=CIRLegacySearch(functions[fid],local_origins[fid],runtime.session.cfg(fid),port,
                input_sites=sites,image_base=base,summaries=recipes,is_code=is_code,is_data=is_data,bounds=bounds,
                body_token=body_hashes[fid],make_recipe=fid in summaries).run()
            if result.recipe is not None:runtime.recipe_put(fid,context,result.recipe)
            passes[fid]=passes.get(fid,0)+1;prefix='function-'+hex(fid.rva+base)+'-pass-'+str(passes[fid])
            write(folder/(prefix+'.json'),{'function':fid.rva+base,
                'sites':[site.to_legacy_dict() for site in result.sites],'pending':result.pending,
                'steps':result.steps,'metrics':result.metrics,'epoch':runtime.epochs[fid],
                'scope':asdict(scope),'wall_seconds':time.monotonic()-tick})
            if archive_enabled:archive_memory(result.snapshot,folder/(prefix+'-memory'))
            if result.recipe is not None:write(folder/(prefix+'-recipe.json'),asdict(result.recipe))
            if archive_enabled:write(folder/(prefix+'-reference.json'),[{'site':site,'recipe':asdict(recipe)} for site,recipe in result.reference_recipes])
            handle=runtime.handle(fid,context)
            for namespace in ('heap','alias','sse','apg'):
                runtime.memory_put(namespace,handle,engine.initial,'native-observation',
                    ('actual-observation',result.steps,result.metrics['dag_unique_nodes']))
            runtime.put('facts',fid,context,'icall',tuple((f.origin,f.targets) for f in result.targets))
            invocations.append({'function':fid.rva+base,'pass':passes[fid],'epoch':runtime.epochs[fid],
                'revision':scope.state_revision,'targets':sum(len(f.targets) for f in result.targets),
                'pending':len(result.pending),'wall_seconds':time.monotonic()-tick})
            print(hex(fid.rva+base),'pass',passes[fid],'targets',invocations[-1]['targets'],'pending',len(result.pending),flush=True)
            return result
        updater=TargetGraphUpdater(runtime,module.origin_map)
        result=CIRProgramSearch(runtime,updater,analyze,max_rounds=args.max_rounds,
            order=lambda todo:callee_first(todo,runtime.session.cg)).run(functions)
        rows=[];actual={};facts=[]
        for fid,outcome in result.results:
            for row in outcome.sites:
                rows.append({'function':fid.rva+base,**row.to_legacy_dict()})
            for fact in outcome.targets:
                address=fact.site.point.instruction_rva+base
                actual.setdefault(str(fid.rva+base),{}).setdefault(str(address),set()).update(fact.targets)
                facts.append({'function':fid.rva+base,'site':address,'targets':fact.targets,'certainty':fact.certainty,
                    'exhaustive':fact.exhaustive,'memory_version':fact.memory.key,'origin':fact.origin})
        logical={(('internal',e.site.function.rva+base),('internal',e.target.rva+base)) for e in runtime.session.cg.edges if e.target is not None}
        logical|={(('internal',f.rva+base),('external',name)) for f,site,name in index.external_calls}
        write(folder/'target-facts.json',facts);write(folder/'site-coverage.json',rows)
        write(folder/'cg-logical-edges.json',sorted(logical));write(folder/'invalidation-events.json',runtime.events)
        write(folder/'invocations.json',invocations)
        # Reference files are deliberately opened only after analysis finishes.
        old=json.loads(args.legacy_cg.read_text(encoding='utf8'))
        old_cg={tuple(tuple(x) for x in pair) for pair in old['warm_edges']}
        cold_logical={(('internal',e.site.function.rva+base),('internal',e.target.rva+base)) for e in index.cg.edges if e.target is not None}
        cold_logical|={(('internal',f.rva+base),('external',name)) for f,site,name in index.external_calls}
        old_cold={tuple(tuple(x) for x in pair) for pair in old['cold_edges']}
        expected=json.loads((TARGET.parent/'baselines/rv130_1_0_3_44/20261028T051055Z-96d1c781/icall-targets.json').read_text(encoding='utf8'))
        differences=[]
        for function,site in sorted({(f,s) for f,calls in expected.items() for s in calls}|{(f,s) for f,calls in actual.items() for s in calls}):
            a=set(expected.get(function,{}).get(site,()));b=set(actual.get(function,{}).get(site,()))
            differences.append({'function':function,'site':site,'missing':sorted(a-b),'extra':sorted(b-a)})
        write(folder/'differential.json',differences)
        report.update(input_sites=len(input_sites),observed_sites=len(rows),declared_functions=len(index.program.functions),
            cold_metadata_edges=len(index.cg.edges),logical_edges=len(logical),legacy_logical_edges=len(old_cg),
            cg_missing=sorted(old_cg-logical),cg_extra=sorted(logical-old_cg),cg_version=runtime.session.cg_version,
            missing=sum(len(x['missing']) for x in differences),extra=sum(len(x['extra']) for x in differences),
            derived_target_entries=sum(len(v) for calls in actual.values() for v in calls.values()),rounds=result.rounds,
            invocations=len(invocations),graph_pending=[f.rva+base for f in result.pending],
            function_pending=sum(len(r.pending) for f,r in result.results),
            active_functions=len(runtime.active),metadata_only_invalidated=len(runtime.metadata_invalidated),
            ancestor_passes=passes.get(next((f for f in functions if f.rva+base==0x2e9b4),None),0),
            unmapped_targets=updater.unmapped)
        report.update(cold_logical_edges=len(cold_logical),cold_cg_missing=sorted(old_cold-cold_logical),
            cold_cg_extra=sorted(cold_logical-old_cold),all_input_sites_cfg_reachable=all(r['cfg_reachable'] for r in rows))
        report['passed']=(report['missing']==report['extra']==0 and not report['cg_missing'] and not report['cg_extra']
            and report['observed_sites']==17 and not result.pending and not report['function_pending'] and report['ancestor_passes']>=2
            and not report['cold_cg_missing'] and not report['cold_cg_extra'] and report['all_input_sites_cfg_reachable'])
        # Controlled in-memory semantic change against actual callee/caller CIR.
        # It is deliberately performed after recording the unmodified result.
        # No source, CIR, loader input or reference artifact is changed.
        archive_enabled=False
        context=ContextId();callee=next(f for f in functions if f.rva+base==0x23dc4)
        caller=next(f for f in functions if f.rva+base==0x2d394)
        actual_recipe=runtime.recipe_get(callee,context)
        if actual_recipe is None:raise ValueError('Real callee recipe missing before revision test')
        port=current_ports[caller];old_handle=runtime.handle(caller,context)
        for family in runtime.NAMESPACES:runtime.put(family,caller,context,'revision-marker',('native',))
        injected=replace(actual_recipe,nodes=(SummaryNode(ValueType.bv(32),'constant',value=0),),
                         returns=(0,),stores=(),argument_uses=(),write_regions=(),unknown_effects=False,
                         provenance=('Controlled revision test; not an analysis result',))
        affected=runtime.recipe_put(callee,context,injected)
        evicted=all(runtime.get(family,caller,context,'revision-marker') is None for family in runtime.NAMESPACES)
        stale=False
        try:port.constant(1,ValueType.bv(32),local_origins[caller][0].id)
        except StaleAnalysis:stale=True
        stale_handle=False
        try:runtime.memory_get('heap',old_handle,port.engine.initial,'native-observation')
        except StaleAnalysis:stale_handle=True
        changed=analyze(caller);updater.apply(changed.targets)
        changed_count=sum(len(f.targets) for f in changed.targets)
        unknown_kept=any(e.site.function==caller and e.site.point.instruction_rva+base==0x2d560 and e.target is None for e in runtime.session.cg.edges)
        removed=not any(e.site.function==caller and e.site.point.instruction_rva+base==0x2d560 and e.target is not None and e.reason.startswith(runtime.INFERRED_PREFIX) for e in runtime.session.cg.edges)
        runtime.recipe_put(callee,context,actual_recipe)
        restored=CIRProgramSearch(runtime,updater,analyze,max_rounds=args.max_rounds,
            order=lambda todo:callee_first(todo,runtime.session.cg)).run(functions)
        restored_caller=next(r for f,r in restored.results if f==caller)
        restored_count=sum(len(f.targets) for f in restored_caller.targets)
        restored_logical={(('internal',e.site.function.rva+base),('internal',e.target.rva+base)) for e in runtime.session.cg.edges if e.target is not None}
        restored_logical|={(('internal',f.rva+base),('external',name)) for f,site,name in index.external_calls}
        revision={'affected':sorted(f.rva+base for f in affected),'all_cache_families_evicted':evicted,
            'old_port_rejected':stale,'old_handle_rejected':stale_handle,'injected_target_entries':changed_count,
            'derived_edges_retracted':removed,'unknown_edge_preserved':unknown_kept,'restored_target_entries':restored_count,
            'restored_cg_equal':restored_logical==logical,'pending':[f.rva+base for f in restored.pending],
            'restored_function_pending':sum(len(r.pending) for f,r in restored.results)}
        revision['passed']=all((evicted,stale,stale_handle,changed_count==0,removed,unknown_kept,restored_count==61,
            restored_logical==logical,not restored.pending,not revision['restored_function_pending']))
        write(folder/'native-revision-test.json',revision)
        write(folder/'revision-invocations.json',invocations)
        write(folder/'revision-invalidation-events.json',runtime.events)
        report['native_revision_passed']=revision['passed'];report['passed'] &= revision['passed']
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['source_hashes']=source_hashes
        report['sources_unchanged']=all(hashlib.sha256((TARGET/n).read_bytes()).hexdigest()==h for n,h in source_hashes.items())
        report['violations']=guard.violations;report['wall_seconds']=time.monotonic()-started
        report['passed']=report.get('passed',False) and report['sources_unchanged'] and not guard.violations
        with (folder/'integration-report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2,default=str)
        guard.restore()
    print(json.dumps({k:v for k,v in report.items() if k!='source_hashes'}),flush=True)
    return 0 if report.get('passed') and not report['violations'] else 1

if __name__=='__main__':raise SystemExit(main())
