"""P6 continuation acceptance, preserving the earlier partial-phase validator.

All evidence uses fresh directories. Source changes authorized in this P6 are
audited explicitly; old repositories, environments and sealed runs stay frozen.
"""
import argparse
import ast
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import subprocess
import sys
import uuid
from baseline_inventory import full_inventory
from p6_validate import command,write
TARGET=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('evidence',type=Path)
    evidence=parser.parse_args().evidence.resolve();evidence.relative_to(TARGET/'.p6-work')
    folder=evidence/('acceptance-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);folder.mkdir(exist_ok=False)
    print('ACCEPTANCE_FOLDER='+str(folder),flush=True)
    python=str(TARGET/'.venv/Scripts/python.exe');legacy=str(TARGET.parent/'EmTaint/.venv/Scripts/python.exe')
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env.pop('PYTHONPATH',None);env.pop('VIRTUAL_ENV',None)
    sources={p.relative_to(TARGET).as_posix():hashlib.sha256(p.read_bytes()).hexdigest()
        for root in ('emtaint','scripts','tests') for p in (TARGET/root).rglob('*.py')}
    write(folder/'source-manifest.json',sources)
    for name in ('legacy','cir'):(folder/name).mkdir()
    specs=[
        ('pure-p6',[python,'-B','-S','-m','unittest','discover','-s','tests','-p','test_p6*.py','-v']),
        ('all-tests',[python,'-B','-m','unittest','discover','-s','tests','-v']),
        ('native-scalar-and-p4',[python,'-B','scripts/p6_scalar_probe.py','--folder',str(folder/'scalar')]),
        ('legacy-characterization',[legacy,'-B','scripts/p6_legacy_probe.py','--folder',str(folder/'legacy')]),
        ('old-loader',[legacy,'-B','scripts/p6_loader_probe.py','--legacy','--folder',str(folder/'old-loader')]),
        ('new-loader',[python,'-B','scripts/p6_loader_probe.py','--folder',str(folder/'new-loader')]),
        ('cir-acquisition',[python,'-B','scripts/p6_probe.py','--folder',str(folder/'cir'),'--legacy-report',str(folder/'legacy/legacy-report.json'),
            '--lift-only','--extra-functions','0x1ea0c','0x23dc4','0x29590','0x2e9b4','--summary-dependency-closure',
            '--summary-seeds','0x1ea0c','0x23dc4','0x29590']),
        ('integration',[python,'-B','scripts/p6_integration_probe.py','--folder',str(folder/'integration'),
            '--cir-folder',str(folder/'cir'),'--loader',str(folder/'new-loader'),'--legacy-cg',str(folder/'legacy/legacy-cg.json')]),
        ('same-cir-old-collector',[legacy,'-B','scripts/p6_reference_probe.py','--folder',str(folder/'reference'),
            '--integration',str(folder/'integration'),'--loader',str(folder/'old-loader')]),
        ('diff-check',['git','--no-optional-locks','diff','--check','--','.',':!.venv'])]
    receipts=[]
    for label,argv in specs:
        receipt=command(folder,label,argv,env,deadline=1800);receipts.append(receipt)
        write(folder/(label+'-receipt.json'),receipt)
        if receipt['exit_code'] or receipt['timed_out']:
            write(folder/'failed-command.json',receipt);print('REPAIR_REQUIRED='+label,flush=True);return 1
    write(folder/'commands.json',receipts)
    load=lambda path:json.loads(path.read_text(encoding='utf8'))
    old_loader=load(folder/'old-loader/loader.json');new_loader=load(folder/'new-loader/loader.json')
    loader_equal=(old_loader['binary_sha256']==new_loader['binary_sha256'] and old_loader['segments']==new_loader['segments']
        and old_loader['relocations']==new_loader['relocations'] and old_loader['reads']==new_loader['reads'])
    write(folder/'loader-differential.json',{'all_segment_bytes_equal':loader_equal,'relocations':new_loader['relocations'],
        'old':old_loader['angr'],'new':new_loader['angr'],'sections_equal':old_loader['sections']==new_loader['sections']})
    prior=TARGET/'.p6-work/20261029T015236Z-8436ab4c'
    roots={'legacy':TARGET.parent/'EmTaint','target-venv':TARGET/'.venv','golden':TARGET.parent/'baselines','p6-prior':prior}
    previous={'p1-sealed':TARGET/'.p1-work/20261028T081314Z-a53352b3','p2-sealed':TARGET/'.p2-work/20261028T083140Z-bcf22249',
        'p3-sealed':TARGET/'.p3-work/20261028T090527Z-dba03447','p4-sealed':TARGET/'.p4-work/20261028T120656Z-ef8a592c',
        'p5-sealed':TARGET/'.p5-work/20261028T144038Z-ee69d677'}
    integrity={}
    for name,root in {**roots,**previous}.items():
        after=full_inventory(root);before=load((evidence if name in roots else prior)/(name+'-before.json'))
        write(folder/(name+'-after.json'),after)
        integrity[name]={'files':len(after),'unchanged':after==before};print(json.dumps({name:integrity[name]}),flush=True)
    documents={n:(TARGET/n).read_bytes()==(evidence/'planning-source'/n).read_bytes() for n in ('AGENTS.md','MIGRATION_BLUEPRINT.md','CODE_TASK.md')}
    before={r['path']:r for r in load(evidence/'target-source-before.json')}
    after={r['path']:r for r in full_inventory(TARGET/'emtaint')}
    changes=[{'file':'emtaint/'+n,'before_sha256':before.get(n,{}).get('sha256'),'after_sha256':after.get(n,{}).get('sha256')}
        for n in sorted(before.keys()|after.keys()) if before.get(n,{}).get('sha256')!=after.get(n,{}).get('sha256')]
    write(folder/'authorized-source-changes.json',changes)
    schema_names=[n for n in before if n.startswith('ir/canonical/') or n=='core/contracts.py' or n in
        ('memory/abstract_heap.py','memory/access_graph.py','memory/access_path.py','memory/memory_version.py','memory/state.py','memory/query_port.py')]
    schema={n:before[n]['sha256']==after.get(n,{}).get('sha256') for n in schema_names};write(folder/'frozen-schema.json',schema)
    forbidden=[];whitespace=[];retained_native=[];retained_whitespace=[];pure_imports=[]
    pure_prefixes=('emtaint/core/','emtaint/ir/canonical/','emtaint/graph/','emtaint/memory/',
        'emtaint/analysis/dataflow/','emtaint/analysis/framework/','emtaint/analysis/controlflow/',
        'emtaint/analysis/sse/','emtaint/analysis/taint/','emtaint/orchestration/')
    for name in sources:
        path=TARGET/name;text=path.read_text(encoding='utf-8-sig');tree=ast.parse(text,str(path))
        baseline=before.get(name.removeprefix('emtaint/'),{}).get('sha256') if name.startswith('emtaint/') else None
        same=baseline==hashlib.sha256(path.read_bytes()).hexdigest()
        if any(line!=line.rstrip() for line in text.splitlines()):
            if same and not name.startswith(pure_prefixes):retained_whitespace.append(name)
            else:whitespace.append(name)
        for node in ast.walk(tree):
            names=[node.module] if isinstance(node,ast.ImportFrom) else [v.name for v in node.names] if isinstance(node,ast.Import) else []
            if name.startswith(pure_prefixes):pure_imports.extend((name,n) for n in names if n)
            native=[n for n in names if n and n.split('.')[0] in ('angr','pyvex','claripy','z3','idaapi','ida_hexrays')]
            if name.startswith(pure_prefixes):forbidden.extend(name+':'+n for n in native)
            elif name.startswith(('emtaint/ir/','emtaint/analysis/')):
                retained_native.extend({'file':name,'import':n,'unchanged_from_phase_start':same} for n in native)
    legacy_modules={r['file'][:-3].replace('/','.') for r in retained_native}
    legacy_dependencies=[file+':'+module for file,module in pure_imports if any(module==n or module.startswith(n+'.') for n in legacy_modules)]
    legacy_unchanged=all(r['unchanged_from_phase_start'] for r in retained_native)
    write(folder/'native-boundary-audit.json',{'pure_core_prefixes':pure_prefixes,'forbidden':forbidden,
        'retained_pre_migration_native_wrappers':retained_native,'pure_core_dependencies_on_native_wrappers':legacy_dependencies,
        'retained_unchanged_whitespace':retained_whitespace,
        'scope':'P6 migrated CIR core is pure; pre-migration target VEX wrappers remain as frozen compatibility code, not a claim that the entire repository has no native imports'})
    source_equal=all(hashlib.sha256((TARGET/n).read_bytes()).hexdigest()==h for n,h in sources.items())
    integration=load(folder/'integration/integration-report.json');reference=load(folder/'reference/reference-report.json')
    arenas=[]
    for manifest_path in (folder/'integration').glob('*-memory/manifest.json'):
        manifest=load(manifest_path)
        for entry in [manifest[k] for k in ('scope','architecture','budgets','assessment')]+list(manifest['groups'].values()):
            if hashlib.sha256((manifest_path.parent/entry['file']).read_bytes()).hexdigest()!=entry['sha256']:raise ValueError('Arena hash mismatch')
        arenas.append({'folder':manifest_path.parent.name,'groups':manifest['groups'],'total_record_bytes':manifest['total_record_bytes']})
    write(folder/'arena-integrity.json',{'all_hashes_verified':True,'full_decode':'Unit round-trip/tamper test; native records encoded with unchanged P3 codec','arenas':arenas})
    quality=(all(r['exit_code']==0 and not r['timed_out'] for r in receipts) and loader_equal and all(r['unchanged'] for r in integrity.values())
        and all(documents.values()) and all(schema.values()) and not forbidden and not whitespace and source_equal and legacy_unchanged and not legacy_dependencies)
    phase=quality and integration['passed'] and integration['sources_unchanged'] and reference['passed'] and integration['native_revision_passed']
    result={'phase':'P6','quality_gate':'PASS' if quality else 'FAIL','phase_gate':'PASS' if phase else 'NOT_PASSED',
        'state':'complete' if phase else 'failed','commands':receipts,'integrity':integrity,'planning_docs_unchanged':documents,
        'frozen_schema_unchanged':all(schema.values()),'forbidden_core_imports':forbidden,'trailing_whitespace':whitespace,
        'retained_native_compatibility_unchanged':legacy_unchanged,'pure_core_legacy_dependencies':legacy_dependencies,
        'all_python_sources_unchanged_during_validation':source_equal,'runtime_packages':{n:importlib.metadata.version(n) for n in ('angr','claripy','pyvex','cle','archinfo','z3-solver','psutil')},
        'python':sys.version,'executable':sys.executable,'loader_equal':loader_equal,'integration':integration,
        'same_cir_old_collector':reference,'legacy_cli':'NOT_EXECUTED; actual old methods/loader/Collector read-only probes',
        'p7':'NOT_STARTED','gate_a':'NOT_EVALUATED','rust':'NOT_IMPLEMENTED'}
    write(folder/'validation-p6.json',result)
    print('VALIDATION='+str(folder/'validation-p6.json'),flush=True);print('P6='+result['phase_gate'],flush=True)
    return 0 if phase else 1


if __name__=='__main__':raise SystemExit(main())
