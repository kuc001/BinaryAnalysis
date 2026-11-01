"""P5 final gate, fresh guarded probes, full regression and immutable inputs."""
import argparse
import ast
import datetime as dt
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid
import psutil
from baseline_inventory import full_inventory

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET))
from emtaint.solver.process_port import terminate_tree


def write(path,value):
    with path.open('x',encoding='utf8') as f:json.dump(value,f,indent=2)


def command(folder,label,args,env):
    started=time.monotonic();peak=0;timed_out=False
    with (folder/(label+'.stdout.txt')).open('xb') as out,(folder/(label+'.stderr.txt')).open('xb') as err:
        process=subprocess.Popen(args,cwd=TARGET,env=env,stdout=out,stderr=err)
        while process.poll() is None:
            try:
                root=psutil.Process(process.pid);members=[root]+root.children(recursive=True)
                rss=0
                for member in members:
                    try:rss+=member.memory_info().rss
                    except psutil.NoSuchProcess:pass
                peak=max(peak,rss)
            except psutil.NoSuchProcess:pass
            if time.monotonic()-started>240:
                terminate_tree(process);timed_out=True;break
            time.sleep(.05)
    stderr=(folder/(label+'.stderr.txt')).read_text(encoding='utf8',errors='replace')
    match=re.search(r'Ran (\d+) tests',stderr)
    result={'name':label,'command':args,'exit_code':process.returncode,'timed_out':timed_out,
        'tests':int(match.group(1)) if match else None,'wall_seconds':time.monotonic()-started,
        'peak_rss_sampled_bytes':peak or None,'rss_scope':'50ms samples, sum launcher and child RSS; not exact peak or isolated kernel memory'}
    print(json.dumps(result),flush=True);return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('evidence',type=Path)
    evidence=parser.parse_args().evidence.resolve();evidence.relative_to(TARGET/'.p5-work')
    if not (evidence/'legacy-before.json').exists():raise ValueError('Phase-start inventories required')
    folder=evidence/('validation-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8])
    folder.mkdir(exist_ok=False)
    for name in ('legacy','native','conformance'):(folder/name).mkdir()
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env.pop('PYTHONPATH',None);env.pop('VIRTUAL_ENV',None)
    python=str(TARGET/'.venv/Scripts/python.exe');legacy=str(TARGET.parent/'EmTaint/.venv/Scripts/python.exe')
    specs=(
        ('pure-memory-tests',[python,'-B','-S','-m','unittest','discover','-s','tests','-p','test_p5*.py','-v']),
        ('all-tests',[python,'-B','-m','unittest','discover','-s','tests','-v']),
        ('legacy-characterization',[legacy,'-B','scripts/p5_legacy_probe.py','--folder',str(folder/'legacy')]),
        ('native-solver',[python,'-B','scripts/p5_native_probe.py','--folder',str(folder/'native'),
            '--legacy-report',str(folder/'legacy/legacy-report.json')]),
        ('memory-conformance',[python,'-B','-S','scripts/p5_conformance.py','--folder',str(folder/'conformance')]),
        ('diff-check',['git','--no-optional-locks','diff','--check','--','.',':!.venv']),)
    receipts=[command(folder,label,args,env) for label,args in specs]
    write(folder/'commands.json',receipts)
    reports={}
    for key,path in (('legacy','legacy/legacy-report.json'),('native','native/native-report.json'),('conformance','conformance/conformance-report.json')):
        reports[key]=json.loads((folder/path).read_text(encoding='utf8')) if (folder/path).exists() else {'passed':False}
    roots={'legacy':TARGET.parent/'EmTaint','target-venv':TARGET/'.venv','golden':TARGET.parent/'baselines',
        'p1-sealed':TARGET/'.p1-work/20261028T081314Z-a53352b3','p2-sealed':TARGET/'.p2-work/20261028T083140Z-bcf22249',
        'p3-sealed':TARGET/'.p3-work/20261028T090527Z-dba03447','p4-sealed':TARGET/'.p4-work/20261028T120656Z-ef8a592c',
        'p3-ir':TARGET/'emtaint/ir','old-frontend':TARGET/'emtaint/frontend','p4-frontends':TARGET/'emtaint/frontends'}
    integrity={}
    for name,root in roots.items():
        after=full_inventory(root);write(folder/(name+'-after.json'),after)
        before=json.loads((evidence/(name+'-before.json')).read_text(encoding='utf8'))
        integrity[name]={'files':len(after),'unchanged':before==after};print(json.dumps({name:integrity[name]}),flush=True)
    docs={n:(TARGET/n).read_bytes()==(evidence/'planning-source'/n).read_bytes() for n in ('AGENTS.md','MIGRATION_BLUEPRINT.md','CODE_TASK.md')}
    source=TARGET/'.p3-work/20261028T090527Z-dba03447/final-source'
    frozen=all((TARGET/f.relative_to(source)).read_bytes()==f.read_bytes() for f in source.rglob('*') if f.is_file() and f.suffix in ('.py','.json'))
    # Existing P3 files remain byte-identical. Only P5 runtime extensions are new.
    files=list((TARGET/'emtaint/analysis/sse').rglob('*.py'))+list((TARGET/'emtaint/analysis/taint').rglob('*.py'))
    files += [TARGET/'emtaint/memory'/n for n in ('policies.py','access_graph.py','engine.py','memory_version.py','cir.py')]
    files += [TARGET/'emtaint/compat/sse.py',TARGET/'emtaint/solver/memory_lowering.py']
    files += list((TARGET/'tests').glob('test_p5*.py'))+[TARGET/'tests/conformance/memory/runtime_fixtures.py',TARGET/'tests/conformance/memory/test_runtime.py']
    files += list((TARGET/'scripts').glob('p5_*.py'))
    forbidden=[]
    for file in files:
        text=file.read_text(encoding='utf-8-sig');tree=ast.parse(text,str(file))
        if any(line!=line.rstrip() for line in text.splitlines()):raise ValueError('Trailing whitespace: '+str(file))
        if 'emtaint/memory' in file.as_posix() or 'emtaint/analysis' in file.as_posix():
            for node in ast.walk(tree):
                names=([node.module] if isinstance(node,ast.ImportFrom) else [x.name for x in node.names] if isinstance(node,ast.Import) else [])
                forbidden += [str(file)+':'+name for name in names if name and name.split('.')[0] in ('angr','pyvex','claripy','z3','idaapi','ida_hexrays')]
    versions={n:importlib.metadata.version(n) for n in ('angr','claripy','pyvex','cle','archinfo','z3-solver','psutil')}
    git={}
    for label,root in (('target',TARGET),('legacy',TARGET.parent/'EmTaint')):
        git[label]={'commit':subprocess.check_output(['git','--no-optional-locks','-C',str(root),'rev-parse','HEAD'],text=True).strip(),
            'status':subprocess.check_output(['git','--no-optional-locks','-C',str(root),'status','--short','--','.',':!.venv'],text=True)}
    write(folder/'git-state.json',git)
    passed=all(r['exit_code']==0 and not r['timed_out'] for r in receipts) and all(r.get('passed') for r in reports.values())
    passed=passed and all(x['unchanged'] for x in integrity.values()) and all(docs.values()) and frozen and not forbidden
    result={'phase':'P5','gate_m':'PASS' if passed else 'FAIL','scope':'Bounded Python Memory-Semantics-v1 conformance and legacy characterization; explicit unsupported/incomplete outside scope',
        'commands':receipts,'integrity':integrity,'planning_docs_unchanged':docs,'p3_contracts_and_schemas_unchanged':frozen,
        'forbidden_core_imports':forbidden,'python':sys.version,'executable':sys.executable,'runtime_packages':versions,
        'legacy_environment':reports['legacy'].get('python'),'legacy_executable':reports['legacy'].get('executable'),
        'native_cases':len(reports['native'].get('cases',[])),'runtime_fixtures':len(reports['conformance'].get('cases',[])),
        'reference_differential':reports['native'].get('legacy_differential'),
        'golden_differential':'Seeded concrete table replay only; full -i/-t NOT_EXECUTED / P6-P7',
        'gate_a':'NOT_EXECUTED','rust':'NOT_IMPLEMENTED','default_memory_engine':'legacy (SDK requires supplied reference instance; CLI default unchanged)'}
    write(folder/'validation-p5.json',result)
    print('VALIDATION='+str(folder/'validation-p5.json'),flush=True);print('P5 GATE M='+result['gate_m'],flush=True)
    return 0 if passed else 1


if __name__=='__main__':raise SystemExit(main())
