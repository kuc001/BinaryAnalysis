"""Bounded taint-demand diagnosis with per-function receipts and stack samples."""
import argparse
import cProfile
from dataclasses import asdict
import faulthandler
import json
import os
from pathlib import Path
import sys
import time
import tempfile
import traceback
TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET))
from p1_runtime import ProbeWriteGuard
from emtaint.frontends.function_store import FunctionStore
from emtaint.frontends.inputs import read_ida_cfg
from emtaint.core import ContextId
from emtaint.core.contracts import AnalysisScope,SemanticBudgets
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.taint.demand import LegacyTaintDemand,dependency_order
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.analysis.taint.evidence import summary_evidence,focused_snapshot
from emtaint.results.memory_archive import archive_memory


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--acquisition',type=Path,required=True);parser.add_argument('--icall',type=Path,required=True)
    parser.add_argument('--count',type=int,default=30);parser.add_argument('--function',type=lambda x:int(x,0))
    parser.add_argument('--uncached-queries',action='store_true')
    parser.add_argument('--functions',nargs='+',type=lambda x:int(x,0))
    parser.add_argument('--binary',type=Path,default=TARGET.parent/'EmTaint/firmware-binaries/rv130_v44/httpd')
    parser.add_argument('--no-stacks',action='store_true',help='Disable the background traceback sampler during native-crash diagnosis')
    parser.add_argument('--no-profile',action='store_true')
    parser.add_argument('--sample-stacks',action='store_true',help='Opt in to the separately diagnosed Windows traceback sampler')
    parser.add_argument('--passes',type=int,default=1)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for key in ('TEMP','TMP','TMPDIR'):os.environ[key]=str(cache)
    tempfile.tempdir=str(cache)
    guard=ProbeWriteGuard([folder]).install();store=FunctionStore(args.acquisition,binary=args.binary)
    specs=read_ida_cfg(TARGET.parent/'EmTaint/data/ida_data/rv130_1_0_3_44/httpd_cfg.json');by_address={s.address:s for s in specs}
    targets={int(site):values for rows in json.loads(args.icall.read_text()).values() for site,values in rows.items()}
    children={s.address:{c.target for c in s.calls if type(c.target) is int} for s in specs}
    for f,rows in json.loads(args.icall.read_text()).items():
        for values in rows.values():children[int(f)].update(values)
    done=set();visiting=set();ordered=[]
    for root in sorted(children):
        pending=[(root,False)]
        while pending:
            current,ready=pending.pop()
            if current in done or current not in children:continue
            if ready:visiting.discard(current);done.add(current);ordered.append(current);continue
            if current in visiting:continue
            visiting.add(current);pending.append((current,True));pending.extend((c,False) for c in sorted(children[current],reverse=True) if c not in visiting and c not in done)
    summaries={};errors=0;table_bank={}
    try:
        sequence=args.functions if args.functions else [args.function] if args.function else ordered[:args.count]
        for iteration,address in ((iteration,address) for iteration in range(args.passes) for address in sequence):
            output=folder if args.passes==1 else folder/('pass-'+str(iteration+1))
            output.mkdir(exist_ok=True)
            print('START '+hex(address),flush=True);started=time.monotonic();profile=cProfile.Profile()
            if not args.no_profile:profile.enable()
            with (output/(hex(address)+'-stacks.txt')).open('x',encoding='utf8') as stacks:
                if args.sample_stacks and not args.no_stacks and not args.no_profile:faulthandler.dump_traceback_later(20,repeat=True,file=stacks)
                try:
                    module,cfg,digest=store.load(address);print('LOADED '+hex(address),flush=True)
                    fid=module.functions[0].function_id;scope=AnalysisScope(fid,ContextId(),'P7-demand-profile',0,1,iteration)
                    engine=ImageMemoryEngine(scope,module.architecture,module.origin_map,store.segments,
                        SemanticBudgets(sse_nodes=200000,worklist_iterations=2000000),initial_policy='legacy-loader-snapshot')
                    port=MemoryRuntimePort(engine);tick=time.monotonic()
                    def deadline():
                        if time.monotonic()-tick>60:raise DemandLimit('Diagnostic 60 second execution budget')
                    port.validate_current=deadline
                    demand=LegacyTaintDemand(module.functions[0],port,cfg,legacy_entry(CIRAccurateDataFlow(port)),
                        names={c.instruction-store.base:c.target for c in by_address[address].calls if type(c.target) is str},
                        summaries=summaries,targets=targets,image_base=store.base,cache_queries=not args.uncached_queries,tables=dict(table_bank))
                    print('CONSTRUCTED '+hex(address),flush=True)
                    summary=demand.analyze();summaries[address]=summary
                    from dataclasses import replace
                    for root,dependencies in summary.tables:
                        if root.kind=='argument':continue
                        sources=tuple(replace(dep,recipes=(),unresolved_constraints=dep.unresolved_constraints or bool(dep.recipes))
                            for dep in dependencies if dep.kind=='source')
                        table_bank[root]=tuple(sorted(dict.fromkeys(table_bank.get(root,())+sources),key=dependency_order))
                    record={**summary_evidence(summary),'metrics':port.metrics(),'source_facts':[asdict(f) for f in engine.facts],
                        'query_cache':not args.uncached_queries,'transformation':store.transformations.get(address),
                        'unknown_frontiers':sorted(demand.unknown_evidence),
                        'wall_seconds':time.monotonic()-started}
                    if engine.facts:
                        archive_folder=output/(hex(address)+'-source-memory')
                        manifest=archive_memory(focused_snapshot(engine.snapshot()),archive_folder)
                        record['source_memory_evidence']={'directory':str(archive_folder),'groups':manifest['groups']}
                except BaseException as error:
                    traceback.print_exc();record={'error':type(error).__name__+': '+str(error),'wall_seconds':time.monotonic()-started}
                finally:
                    faulthandler.cancel_dump_traceback_later()
                    if not args.no_profile:profile.disable();profile.dump_stats(str(output/(hex(address)+'.pstats')))
            with (output/(hex(address)+'.json')).open('x',encoding='utf8') as stream:json.dump(record,stream,indent=2,default=str)
            if 'error' in record:errors+=1
            print('DONE '+hex(address)+' '+str(round(record['wall_seconds'],3)),flush=True)
        return 1 if errors else 0
    finally:
        with (folder/'probe-report.json').open('x',encoding='utf8') as stream:
            json.dump({'execution_errors':errors,'violations':guard.violations,'execution_ok':not errors and not guard.violations,
                'cprofile':not args.no_profile,'stack_sampler':args.sample_stacks and not args.no_stacks and not args.no_profile},stream,indent=2)
        guard.restore()


if __name__=='__main__':raise SystemExit(main())
