"""Guarded native lifting and actual CIR dataflow on all IDA iCall callers.

Golden target lists are opened only after analysis. They never seed transfer,
heap, registers, target facts or graph construction.
"""
import argparse
import ctypes
import faulthandler
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import traceback

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET));sys.path.insert(0,str(TARGET/'tests'))
from p1_runtime import ProbeWriteGuard


def write(path,value):
    with path.open('x',encoding='utf8') as f:json.dump(value,f,indent=2)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,required=True);parser.add_argument('--legacy-report',type=Path,required=True)
    parser.add_argument('--functions',type=lambda s:int(s,0),nargs='+')
    parser.add_argument('--wall-seconds',type=float,default=3)
    parser.add_argument('--max-steps',type=int,default=2000)
    parser.add_argument('--max-rounds',type=int,default=2)
    parser.add_argument('--lift-only',action='store_true')
    parser.add_argument('--extra-functions',type=lambda s:int(s,0),nargs='+',default=[])
    parser.add_argument('--summary-dependency-closure',action='store_true')
    parser.add_argument('--summary-seeds',type=lambda s:int(s,0),nargs='+')
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p6-work')
    cache=folder/'cache';cache.mkdir(exist_ok=False)
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    if sys.platform=='win32':ctypes.windll.kernel32.SetErrorMode(3)
    faulthandler.enable();guard=ProbeWriteGuard([folder]).install();report={};started=time.monotonic()
    source_files=[]
    for directory in ('emtaint/analysis/dataflow','emtaint/analysis/framework','emtaint/analysis/controlflow','emtaint/orchestration','emtaint/frontends','emtaint/analysis/sse'):
        source_files.extend((TARGET/directory).rglob('*.py'))
    source_files += [TARGET/'emtaint/compat/memory_runtime.py',TARGET/'emtaint/memory/image.py',Path(__file__).resolve()]
    source_hashes={f.relative_to(TARGET).as_posix():hashlib.sha256(f.read_bytes()).hexdigest() for f in source_files}
    try:
        from emtaint.frontends.ida_vex import IdaVexFrontend
        from emtaint.frontends.inputs import read_ida_cfg
        from emtaint.core import (Program,Function,BasicBlock,CallSite,CallKind,BinaryId,FunctionId,
            ContextId,CallSiteId,Completeness)
        from emtaint.core.contracts import AnalysisScope,SemanticBudgets
        from emtaint.ir.canonical import CallEffect,IndirectTarget,JumpEffect,BranchEffect
        from emtaint.ir.canonical.wire import dumps
        from emtaint.memory.image import ImageMemoryEngine
        from emtaint.compat.memory_runtime import MemoryRuntimePort
        from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
        from emtaint.analysis.dataflow.entry import legacy_entry
        from emtaint.analysis.framework.runtime import AnalysisRuntime
        from emtaint.analysis.controlflow.targets import TargetGraphUpdater
        from emtaint.orchestration.fast_search import CIRFastSearch
        from emtaint.orchestration.program_search import CIRProgramSearch
        from emtaint.analysis.dataflow.fast import CIRFastDataFlow
        from emtaint.core.contracts import ValueRef,ValueType,Producer,Origin
        from emtaint.ir.canonical import ReadRegister,RegisterSlice,WriteRegister,RegisterWritePolicy,Compute,ValueOp
        from emtaint.core.contracts import Constant
        # Actual legacy scalar backward test, normalized to the same CIR chain.
        legacy=json.loads(args.legacy_report.read_text(encoding='utf8'))
        t0=ValueRef('t0',ValueType.bv(32));t1=ValueRef('t1',ValueType.bv(32));truth=Constant(True,ValueType.boolean())
        effects=(ReadRegister('0',t0,RegisterSlice('r1',0,32,32)),
            Compute('1',t1,ValueOp.ADD,(t0,Constant(8,t0.type))),
            WriteRegister('2',RegisterSlice('r0',0,32,32),t1,RegisterWritePolicy.FULL,truth))
        scalar=CIRFastDataFlow().slice(effects,('reg:r0',))
        internal=[list(x) for x in sorted((int(a),int(b)) for a,b in scalar.dependencies)]
        old_internal=[pair for pair in legacy['fast']['edges'] if pair[1]<3]
        report['legacy_differential']={'inputs_equal':list(scalar.inputs)==legacy['fast']['inputs'],
            'internal_edges_equal':internal==old_internal,'legacy':legacy['fast'],
            'cir':{'inputs':list(scalar.inputs),'internal_edges':internal},
            'scope':'Actual old backward scalar chain; final output anchor is external to CIR slice',
            'passed':list(scalar.inputs)==legacy['fast']['inputs'] and internal==old_internal}
        binary=TARGET.parent/'EmTaint/firmware-binaries/rv130_v44/httpd'
        data=TARGET.parent/'EmTaint/data/ida_data/rv130_1_0_3_44'
        info=json.loads((data/'httpd_block_info.json').read_text(encoding='utf8'))
        input_sites=sorted((int(function,16),row[0]) for function,blocks in info.items()
            for rows in blocks.values() for row in rows if row[-1]=='iCall')
        selected={f for f,site in input_sites}
        if args.functions:
            selected &= set(args.functions)
            input_sites=[(f,s) for f,s in input_sites if f in selected]
        selected |= set(args.extra_functions)
        specifications=read_ida_cfg(data/'httpd_cfg.json')
        if args.summary_dependency_closure:
            by_address={s.address:s for s in specifications};todo=list(args.summary_seeds or args.extra_functions);seen=set()
            while todo:
                address=todo.pop()
                if address in seen or address not in by_address:continue
                seen.add(address)
                todo.extend(c.target for c in by_address[address].calls if type(c.target) is int)
            selected |= seen
        frontend=IdaVexFrontend(binary)
        print('lifting '+str(len(selected))+' IDA iCall caller functions',flush=True)
        lift_start=time.monotonic();lifted=frontend.from_metadata(data/'httpd_cfg.json',function_addresses=tuple(sorted(selected)))
        report['lift_seconds']=time.monotonic()-lift_start
        module=lifted.module;image=frontend.image;origins={o.id:o for o in module.origin_map}
        functions={f.function_id:f for f in module.functions};all_ids={FunctionId(BinaryId(module.binary_sha256),s.address-image.image_base):s.name for s in specifications}
        indirect_sites={};calls={}
        for function in module.functions:
            for block in function.blocks:
                for effect in block.effects:
                    if isinstance(effect,CallEffect):calls[effect.site]=CallSite(effect.site,CallKind.INDIRECT if isinstance(effect.target,IndirectTarget) else CallKind.DIRECT)
                    elif isinstance(effect,JumpEffect) and not hasattr(effect.target,'function'):
                        point=origins[effect.origin].point
                        if (image.image_base+function.function_id.rva,image.image_base+point.instruction_rva) in input_sites:
                            site=CallSiteId(point);calls[site]=CallSite(site,CallKind.INDIRECT);indirect_sites[effect.origin]=site
        program_functions=[]
        for id_,name in all_ids.items():
            function=functions.get(id_)
            if function is None:program_functions.append(Function(id_,name));continue
            blocks=[]
            for block in function.blocks:
                points=[o.point.instruction_rva for o in module.origin_map if o.point.block==block.id and o.point.instruction_rva is not None]
                size=max((x-block.id.rva+1 for x in points),default=1)
                blocks.append(BasicBlock(block.id,max(block.size_bytes or 1,size)))
            program_functions.append(Function(id_,name,tuple(blocks),function.entry))
        program=Program(BinaryId(module.binary_sha256),module.architecture,module.functions[0].abi,
            tuple(program_functions),tuple(calls.values()),image.image_base,Completeness.INCOMPLETE,
            ('Only iCall-caller bodies lifted; other functions have metadata identities, not summaries',))
        runtime=AnalysisRuntime(program)
        for cfg in lifted.cfgs():runtime.replace_cfg(cfg)
        runtime.pending.clear()
        extra_exits={}
        translated={effect.origin for function in module.functions for block in function.blocks
                    for effect in block.effects if isinstance(effect,BranchEffect)}
        for row in lifted.metadata.get('native_control_flow',()):
            if 'guard_class' not in row or row['kind']!='Ijk_Boring':continue
            if row['origin'] in translated:continue
            origin=origins[row['origin']]
            targets=[block.id for f in module.functions if f.function_id==origin.point.function
                for block in f.blocks if block.id.rva+image.image_base==row['target']]
            if targets:extra_exits[row['origin']]=tuple(targets)
        # Preserve exact pure CIR and input provenance per function, not just counts.
        (folder/'cir').mkdir()
        for function in module.functions:
            text=dumps(function,max_nodes=8000000,max_bytes=256*1024*1024)
            with (folder/'cir'/('function-'+hex(function.function_id.rva)+'.json')).open('x',encoding='utf8') as out:out.write(text)
        write(folder/'frontend-report.json',lifted.report())
        for name,value in (('architecture',module.architecture),('producer',module.producer),('assessment',module.assessment)):
            with (folder/(name+'.json')).open('x',encoding='utf8') as stream:stream.write(dumps(value))
        write(folder/'origins.json',{o.id:{'block':o.point.block.token,'statement_index':o.point.statement,
            'instruction_rva':o.point.instruction_rva,'source_opcode':o.source_opcode} for o in module.origin_map})
        if args.lift_only:
            report.update(passed=True,lift_only=True,phase_acceptance='NOT_RUN: CIR acquisition only',
                functions=len(module.functions),cir_blocks=sum(len(f.blocks) for f in module.functions),
                frontend_unsupported_ops=list(module.assessment.unsupported_ops))
            return 0
        segments=tuple((base,image.data[offset:offset+filesz],memsz,flags) for base,offset,filesz,memsz,flags in image.segments)
        function_rows=[]
        def analyze(fid):
            function=functions[fid]
            fid=function.function_id;context=ContextId();scope=AnalysisScope.from_session(runtime.session,fid,context)
            local_origins=tuple(o for o in module.origin_map if o.point.function==fid)
            memory=ImageMemoryEngine(scope,module.architecture,local_origins,segments,SemanticBudgets(),
                                     initial_policy='legacy-loader-snapshot')
            port=MemoryRuntimePort(memory);runtime.bind_port(port,fid,context)
            flow=CIRAccurateDataFlow(port)
            start=time.monotonic();search=CIRFastSearch(function,flow,max_steps=args.max_steps,max_states=4096,
                image_base=image.image_base,extra_exits=extra_exits,input_assessment=module.assessment,
                indirect_sites=indirect_sites,wall_seconds=args.wall_seconds)
            result=search.run(legacy_entry(flow))
            row={'function':image.image_base+fid.rva,'status':result.assessment.status.value,
                'diagnostics':list(result.assessment.diagnostics),'visited_blocks':len(result.visited_blocks),
                'total_blocks':len(function.blocks),'states_steps':result.steps,'pending':len(result.pending),
                'metrics':port.metrics(),'wall_seconds':time.monotonic()-start,
                'icall_facts':sum(f.kind=='icall' for f in result.targets),
                'pass':1+sum(r['function']==image.image_base+fid.rva for r in function_rows)}
            function_rows.append(row);print('function '+hex(row['function'])+' '+str(row['visited_blocks'])+'/'+str(row['total_blocks'])+' blocks '+row['status'],flush=True)
            return result
        updater=TargetGraphUpdater(runtime,module.origin_map)
        program_result=CIRProgramSearch(runtime,updater,analyze,max_rounds=args.max_rounds).run(tuple(functions))
        facts=[fact for _,result in program_result.results for fact in result.targets]
        actual={};fact_rows=[]
        for fact in facts:
            origin=origins[fact.origin];point=origin.point
            address=program.absolute_address(point.instruction_rva) if point.instruction_rva is not None else None
            caller=program.absolute_address(point.function.rva)
            row={'function':caller,'site':address,'kind':fact.kind,'targets':list(fact.targets),
                'certainty':fact.certainty,'exhaustive':fact.exhaustive,'origin':fact.origin,
                'memory_version':fact.memory.key,'guards':[g.key for g in fact.guards],
                'status':fact.assessment.status.value,'precision':fact.assessment.precision.value,
                'precision_loss':list(fact.assessment.precision_loss),'evidence':fact.evidence}
            fact_rows.append(row)
            row['ida_icall_site']=(caller,address) in input_sites
            if fact.kind=='icall' and row['ida_icall_site']:
                actual.setdefault(str(caller),{}).setdefault(str(address),set()).update(fact.targets)
        graph_rows=[{'function':program.absolute_address(e.site.function.rva),
            'site':program.absolute_address(e.site.point.instruction_rva) if e.site.point.instruction_rva is not None else None,
            'target':program.absolute_address(e.target.rva) if e.target else None,'certainty':e.certainty.value,'evidence':e.reason}
            for e in runtime.session.cg.edges]
        write(folder/'target-facts.json',fact_rows);write(folder/'cg-edges.json',graph_rows)
        write(folder/'function-results.json',function_rows)
        site_coverage=[]
        for function,site in input_sites:
            rows=[r for r in fact_rows if r['kind']=='icall' and (r['function'],r['site'])==(function,site)]
            site_coverage.append({'function':function,'site':site,'observations':len(rows),
                'status':'not_reached' if not rows else 'has_candidates' if any(r['targets'] for r in rows) else 'unknown',
                'exhaustive':bool(rows) and all(r['exhaustive'] for r in rows)})
        write(folder/'site-coverage.json',site_coverage)
        print('CIR analysis complete; opening Golden for comparison only',flush=True)
        golden=TARGET.parent/'baselines/rv130_1_0_3_44/20261028T051055Z-96d1c781/icall-targets.json'
        expected=json.loads(golden.read_text(encoding='utf8'));differences=[]
        keys={(f,s) for f,calls_ in expected.items() for s in calls_}|{(f,s) for f,calls_ in actual.items() for s in calls_}
        for function,site in sorted(keys,key=lambda x:(int(x[0]),int(x[1]))):
            old=set(expected.get(function,{}).get(site,[]));new=set(actual.get(function,{}).get(site,()))
            differences.append({'function':function,'site':site,'legacy_targets':sorted(old),'apg_targets':sorted(new),
                'missing':sorted(old-new),'extra':sorted(new-old),
                'status':'unknown_or_not_reached' if not new else 'candidate_only; inspect target-facts provenance'})
        report.update(binary_sha256=image.sha256,input_sites=input_sites,input_functions=len(selected),
            source_blocks=sum(len(s.blocks) for s in specifications if s.address in selected),
            cir_blocks=sum(len(f.blocks) for f in module.functions),frontend_unsupported_ops=list(module.assessment.unsupported_ops),
            functions=function_rows,cg_version=runtime.session.cg_version,cg_edges=len(runtime.session.cg.edges),
            rounds=program_result.rounds,analysis_invocations=program_result.invocations,function_wall_budget_seconds=args.wall_seconds,
            pending_reanalysis=sorted(program.absolute_address(f.rva) for f in runtime.pending),unmapped_targets=updater.unmapped,
            legacy_target_file_sha256=hashlib.sha256(golden.read_bytes()).hexdigest(),
            differential=differences,legacy_target_entries=sum(len(t) for c in expected.values() for t in c.values()),
            missing_target_entries=sum(len(r['missing']) for r in differences),extra_target_entries=sum(len(r['extra']) for r in differences),
            apg_target_entries=sum(len(v) for c in actual.values() for v in c.values()),
            real_i_equivalent=all(not d['missing'] and not d['extra'] for d in differences) and not runtime.pending,
            fallback={'memory_engine':'legacy','status':'Original Python reference retained; NOT rerun or fabricated from Golden'},
            full_legacy_cli='NOT_EXECUTED',taint='NOT_EXECUTED / P7',rust='NOT_IMPLEMENTED')
        report['passed']=report['legacy_differential']['passed'] and len({r['function'] for r in function_rows})==len(selected)
        report['phase_acceptance']='PASS' if report['real_i_equivalent'] else 'PARTIAL: CIR subset works; full P6 iCall/summary fidelity not achieved'
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['runtime_source_hashes']=source_hashes
        report['runtime_sources_unchanged_during_probe']=all(hashlib.sha256((TARGET/name).read_bytes()).hexdigest()==digest for name,digest in source_hashes.items())
        report['violations']=guard.violations;report['passed']=report.get('passed',False) and not guard.violations and report['runtime_sources_unchanged_during_probe']
        report['wall_seconds']=time.monotonic()-started
        write(folder/'native-report.json',report);guard.restore()
    print(json.dumps({k:v for k,v in report.items() if k not in ('functions','differential','unmapped_targets','input_sites')}),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
