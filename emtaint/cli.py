"""Python CLI with explicit inputs and isolated, append-only phase outputs."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys
import time
import uuid
from emtaint.ir.canonical import CIRModule
from emtaint.memory.engine import combine
from emtaint.frontends.function_store import FunctionStore
from emtaint.frontends.inputs import read_ida_cfg
from emtaint.frontends.program_index import build_program_index
from emtaint.orchestration.icall_program import recover_icalls


def write(path,value):
    with path.open('x',encoding='utf8') as stream:json.dump(value,stream,indent=2,default=str)


def source_manifest(root):
    paths=list((root/'emtaint').rglob('*.py'))+[root/'main.py']+[root/'scripts'/name for name in (
        'p1_runtime.py','legacy_readonly_bootstrap.py','p7_legacy_reference.py','legacy_baseline.py','baseline_inventory.py','compare_baseline.py')]
    return {p.relative_to(root).as_posix():hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def process_metadata():
    import importlib.metadata
    import psutil
    memory=psutil.Process().memory_info()
    return {'packages':{name:importlib.metadata.version(name) for name in ('angr','claripy','pyvex','cle','archinfo','z3-solver','psutil')},
        'process_peak_rss_bytes':getattr(memory,'peak_wset',None),
        'process_rss_at_receipt_bytes':memory.rss,
        'rss_scope':'Whole CLI process, including frontend and analysis; peak_wset is the Windows process high-water mark'}


def run_icall(args,store,folder):
    metadata=Path(args.ida_data);info=json.loads((metadata/'httpd_block_info.json').read_text(encoding='utf8'))
    sites=sorted((int(f,16),row[0]) for f,blocks in info.items() for rows in blocks.values() for row in rows if row[-1]=='iCall')
    # Reuse the explicitly validated P6 dependency plan for this approved binary.
    # It is a computation selection, never a target list or Golden input.
    approved='334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787'
    if store.report['binary_sha256']!=approved:raise ValueError('No validated iCall dependency policy for this binary')
    selected={f for f,s in sites}|{0x1ea0c,0x1e9ac,0x1e8a8,0x23dc4,0x29590,0x2e9b4}
    modules=[];cfgs=[];bodies={}
    for address in sorted(selected):
        module,cfg,digest=store.load(address);modules.append(module);cfgs.append(cfg);bodies[module.functions[0].function_id]=digest
    first=modules[0]
    module=CIRModule(first.producer,first.architecture,first.endian,first.binary_sha256,
        tuple(f for m in modules for f in m.functions),tuple(o for m in modules for o in m.origin_map),
        first.capabilities,combine(m.assessment for m in modules))
    specs=read_ida_cfg(metadata/'httpd_cfg.json')
    index=build_program_index(module,specs,store.base,input_sites=sites,native_cfgs=cfgs)
    runtime,result,invocations=recover_icalls(module,index,store.segments,store.loader['sections'],sites,bodies)
    targets={};facts=[];coverage=[]
    for fid,outcome in result.results:
        for row in outcome.sites:coverage.append({'function':fid.rva+store.base,**row})
        for fact in outcome.targets:
            function=fid.rva+store.base;site=fact.site.point.instruction_rva+store.base
            targets.setdefault(str(function),{})[str(site)]=list(fact.targets)
            facts.append({'function':function,'site':site,'targets':fact.targets,'certainty':fact.certainty,
                'exhaustive':fact.exhaustive,'memory_version':asdict(fact.memory),'origin':fact.origin,'assessment':asdict(fact.assessment)})
    logical={(('internal',e.site.function.rva+store.base),('internal',e.target.rva+store.base)) for e in runtime.session.cg.edges if e.target is not None}
    logical|={(('internal',f.rva+store.base),('external',name)) for f,site,name in index.external_calls}
    pending=[{'function':f.rva+store.base,'pending':list(r.pending)} for f,r in result.results if r.pending]
    manifest={'phase':'icall','engine':'python','memory_engine':'apg','binary_sha256':module.binary_sha256,
        'acquisition':str(store.folder.resolve()),'metadata':str(metadata.resolve()),'status':'incomplete' if pending or result.pending else 'candidate_fixed_point',
        'input_sites':len(sites),'observed_sites':len(coverage),'target_entries':sum(len(v) for rows in targets.values() for v in rows.values()),
        'logical_cg_edges':len(logical),'rounds':result.rounds,'function_pending':pending,'graph_pending':[f.rva+store.base for f in result.pending],
        'selected_bodies':sorted(selected),'certainty':'MAY; runtime memory/guard remainder retained','gate_a':'NOT_EVALUATED'}
    manifest['plt_sha256']=store.plt_sha256
    for name,value in (('icall-targets',targets),('target-facts',facts),('site-coverage',coverage),('cg-logical-edges',sorted(logical)),
                       ('invalidation-events',runtime.events),('invocations',invocations),('cir-transformations',store.transformations),
                       ('plt-mapping',{'binary_sha256':module.binary_sha256,'plt':store.plt,'sha256':store.plt_sha256}),('icall',manifest)):write(folder/(name+'.json'),value)
    return manifest


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('-f','--binary_file',required=True);parser.add_argument('-n','--firmware_name',required=True)
    parser.add_argument('-v','--firmware_version',required=True)
    modes=parser.add_mutually_exclusive_group(required=True);modes.add_argument('-i','--icall_check',action='store_true');modes.add_argument('-t','--taint_check',action='store_true')
    parser.add_argument('--ida-data',required=True);parser.add_argument('--acquisition',required=True)
    parser.add_argument('--output',required=True);parser.add_argument('--engine',choices=('python',),default='python')
    parser.add_argument('--memory-engine',choices=('apg','legacy'),default='apg')
    parser.add_argument('--legacy-plan',help='Separately approved physical-copy plan for the real old Python reference')
    parser.add_argument('--legacy-resume-prepared',action='store_true',help='Verify and resume an approved physical copy stopped before parser/main execution')
    parser.add_argument('--function-seconds',type=int,default=120,help='Per-function demand deadline; exhausted frontier stays incomplete')
    parser.add_argument('--taint-rounds',type=int,default=15,help='Summary fixed-point round budget')
    parser.add_argument('--taint-functions',nargs='+',type=lambda value:int(value,0),help='Diagnostic function subset; always reported as incomplete program coverage')
    args=parser.parse_args(argv);folder=Path(args.output).resolve();root=Path(__file__).resolve().parents[1]
    if args.function_seconds<1 or not 1<=args.taint_rounds<=15:raise ValueError('Positive function deadline and 1..15 taint rounds required')
    if args.icall_check and args.taint_functions:raise ValueError('--taint-functions is a -t diagnostic option')
    if (args.memory_engine=='legacy')!=bool(args.legacy_plan):raise ValueError('--memory-engine legacy requires --legacy-plan, which is exclusive to that backend')
    if args.legacy_resume_prepared and (args.memory_engine!='legacy' or not args.icall_check):raise ValueError('Prepared resume requires legacy -i')
    if args.memory_engine=='legacy' and args.taint_functions:raise ValueError('Legacy reference does not support APG diagnostic subsets')
    # The approved migration workspace is the only writable business root.
    folder.relative_to(root);folder.relative_to(root/'.p7-work')
    if args.icall_check:
        if args.legacy_resume_prepared:
            if not folder.is_dir() or (folder/'icall.json').exists():raise ValueError('No unstarted prepared legacy output directory')
        else:folder.mkdir(exist_ok=False)
    elif not folder.is_dir() or not (folder/'icall.json').is_file():raise ValueError('-t requires the same completed -i output directory')
    if args.memory_engine=='legacy':
        sys.path.insert(0,str(root/'scripts'))
        from p7_legacy_reference import execute
        return execute(args,folder)
    cache=folder/('cache-i' if args.icall_check else 'cache-t-'+uuid.uuid4().hex[:8]);cache.mkdir(exist_ok=False)
    import os,tempfile
    for key in ('TEMP','TMP','TMPDIR'):os.environ[key]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    sys.path.insert(0,str(root/'scripts'));from p1_runtime import ProbeWriteGuard
    guard=ProbeWriteGuard([folder]).install();started=time.monotonic()
    try:
        sources=source_manifest(root);write(cache/'source-start.json',sources)
        store=FunctionStore(args.acquisition,binary=args.binary_file)
        if hashlib.sha256(Path(args.binary_file).read_bytes()).hexdigest()!=store.report['binary_sha256']:raise ValueError('Binary/acquisition hash mismatch')
        if hashlib.sha256((Path(args.ida_data)/'httpd_cfg.json').read_bytes()).hexdigest()!=store.report['metadata_sha256']:raise ValueError('IDA CFG/acquisition hash mismatch')
        if args.icall_check:manifest=run_icall(args,store,folder)
        else:
            from emtaint.orchestration.taint_program import run_taint
            manifest=run_taint(args,store,folder)
        write(folder/('icall-command.json' if args.icall_check else 'taint-command-'+uuid.uuid4().hex[:8]+'.json'),
            {'argv':sys.argv if argv is None else argv,'executable':sys.executable,'python':sys.version,
                'source_unchanged_during_run':sources==source_manifest(root),'source_manifest':str(cache/'source-start.json'),
                'wall_seconds':time.monotonic()-started,'violations':guard.violations,**process_metadata()})
    except BaseException as error:
        write(cache/'command-error.json',{'argv':sys.argv if argv is None else argv,'executable':sys.executable,
            'status':'failed','error':type(error).__name__+': '+str(error),
            'wall_seconds':time.monotonic()-started,'violations':guard.violations,**process_metadata()})
        raise
    finally:guard.restore()
    print(json.dumps(manifest,default=str),flush=True)
    return 0 if not guard.violations and manifest['status'] not in ('failed','incomplete') else 2
