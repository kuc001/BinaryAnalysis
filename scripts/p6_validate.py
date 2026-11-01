"""P6 quality and semantic gates are separate. Exit 2 means phase still partial."""
import argparse
import ast
import datetime as dt
import hashlib
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


def command(folder,label,args,env,deadline=300):
    started=time.monotonic();peak=0;timed_out=False
    with (folder/(label+'.stdout.txt')).open('xb') as out,(folder/(label+'.stderr.txt')).open('xb') as err:
        process=subprocess.Popen(args,cwd=TARGET,env=env,stdout=out,stderr=err)
        while process.poll() is None:
            try:
                root=psutil.Process(process.pid);rss=0
                for member in [root]+root.children(recursive=True):
                    try:rss+=member.memory_info().rss
                    except psutil.NoSuchProcess:pass
                peak=max(peak,rss)
            except psutil.NoSuchProcess:pass
            if time.monotonic()-started>deadline:terminate_tree(process);timed_out=True;break
            time.sleep(.1)
    stderr=(folder/(label+'.stderr.txt')).read_text(encoding='utf8',errors='replace')
    matched=re.search(r'Ran (\d+) tests',stderr)
    result={'name':label,'command':args,'exit_code':process.returncode,'timed_out':timed_out,
        'tests':int(matched.group(1)) if matched else None,'wall_seconds':time.monotonic()-started,
        'peak_rss_sampled_bytes':peak or None,'rss_scope':'100ms samples, summed launcher/child RSS; not exact kernel or process peak'}
    print(json.dumps(result),flush=True);return result


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('evidence',type=Path)
    evidence=parser.parse_args().evidence.resolve();evidence.relative_to(TARGET/'.p6-work')
    if not (evidence/'legacy-before.json').exists():raise ValueError('Phase-start inventory required')
    folder=evidence/('validation-'+dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]);folder.mkdir(exist_ok=False)
    (folder/'legacy').mkdir();(folder/'native').mkdir()
    python=str(TARGET/'.venv/Scripts/python.exe');legacy=str(TARGET.parent/'EmTaint/.venv/Scripts/python.exe')
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1';env.pop('PYTHONPATH',None);env.pop('VIRTUAL_ENV',None)
    specs=(
        ('pure-p6-tests',[python,'-B','-S','-m','unittest','discover','-s','tests','-p','test_p6*.py','-v']),
        ('all-tests',[python,'-B','-m','unittest','discover','-s','tests','-v']),
        ('legacy-characterization',[legacy,'-B','scripts/p6_legacy_probe.py','--folder',str(folder/'legacy')]),
        ('native-dataflow',[python,'-B','scripts/p6_probe.py','--folder',str(folder/'native'),'--legacy-report',str(folder/'legacy/legacy-report.json')]),
        ('diff-check',['git','--no-optional-locks','diff','--check','--','.',':!.venv']))
    receipts=[command(folder,label,args,env) for label,args in specs];write(folder/'commands.json',receipts)
    native_path=folder/'native/native-report.json'
    native=json.loads(native_path.read_text(encoding='utf8')) if native_path.exists() else {'passed':False}
    roots={'legacy':TARGET.parent/'EmTaint','target-venv':TARGET/'.venv','golden':TARGET.parent/'baselines',
        'p1-sealed':TARGET/'.p1-work/20261028T081314Z-a53352b3','p2-sealed':TARGET/'.p2-work/20261028T083140Z-bcf22249',
        'p3-sealed':TARGET/'.p3-work/20261028T090527Z-dba03447','p4-sealed':TARGET/'.p4-work/20261028T120656Z-ef8a592c',
        'p5-sealed':TARGET/'.p5-work/20261028T144038Z-ee69d677','target-source':TARGET/'emtaint'}
    integrity={}
    for name,root in roots.items():
        after=full_inventory(root);write(folder/(name+'-after.json'),after)
        before=json.loads((evidence/(name+'-before.json')).read_text(encoding='utf8'))
        if name=='target-source':
            indexed={x['path']:x for x in after}
            unchanged=all(indexed.get(row['path'])==row for row in before)
        else:unchanged=before==after
        integrity[name]={'files':len(after),'original_files_unchanged':unchanged};print(json.dumps({name:integrity[name]}),flush=True)
    documents={name:(TARGET/name).read_bytes()==(evidence/'planning-source'/name).read_bytes() for name in ('AGENTS.md','MIGRATION_BLUEPRINT.md','CODE_TASK.md')}
    source_hashes=native.get('runtime_source_hashes',{})
    source_match=bool(source_hashes) and all(hashlib.sha256((TARGET/name).read_bytes()).hexdigest()==digest for name,digest in source_hashes.items())
    files=[TARGET/name for name in source_hashes]+[Path(__file__).resolve(),TARGET/'scripts/p6_legacy_probe.py']+list((TARGET/'tests').glob('test_p6*.py'))
    forbidden=[]
    for file in files:
        text=file.read_text(encoding='utf-8-sig');tree=ast.parse(text,str(file))
        if any(line!=line.rstrip() for line in text.splitlines()):raise ValueError('Trailing whitespace '+str(file))
        if any(part in file.as_posix() for part in ('emtaint/analysis/','emtaint/memory/','emtaint/orchestration/')):
            for node in ast.walk(tree):
                names=[node.module] if isinstance(node,ast.ImportFrom) else [v.name for v in node.names] if isinstance(node,ast.Import) else []
                forbidden.extend(str(file)+':'+name for name in names if name and name.split('.')[0] in ('angr','pyvex','claripy','z3','idaapi','ida_hexrays'))
    quality=(all(r['exit_code']==0 and not r['timed_out'] for r in receipts) and native.get('passed') and
        source_match and all(x['original_files_unchanged'] for x in integrity.values()) and all(documents.values()) and not forbidden)
    phase=quality and native.get('real_i_equivalent',False)
    versions={n:importlib.metadata.version(n) for n in ('angr','claripy','pyvex','cle','archinfo','z3-solver','psutil')}
    git={}
    for label,root in (('legacy',TARGET.parent/'EmTaint'),('target',TARGET)):
        git[label]={'commit':subprocess.check_output(['git','--no-optional-locks','-C',str(root),'rev-parse','HEAD'],text=True).strip(),
            'status':subprocess.check_output(['git','--no-optional-locks','-C',str(root),'status','--short','--','.',':!.venv'],text=True)}
    write(folder/'git-state.json',git)
    result={'phase':'P6','quality_gate':'PASS' if quality else 'FAIL','phase_gate':'PASS' if phase else 'NOT_PASSED',
        'state':'complete' if phase else 'partial' if quality else 'failed',
        'commands':receipts,'integrity':integrity,'planning_docs_unchanged':documents,'forbidden_core_imports':forbidden,
        'runtime_source_hashes_match_probe':source_match,'runtime_packages':versions,'python':sys.version,'executable':sys.executable,
        'real_i_equivalent':native.get('real_i_equivalent',False),'missing_target_entries':native.get('missing_target_entries'),
        'extra_target_entries':native.get('extra_target_entries'),'default_backend':'Preserved Python legacy path; experiment not selected by default',
        'legacy_cli':'NOT_EXECUTED','p7':'NOT_STARTED','gate_a':'NOT_PASSED / NOT_EVALUATED','rust':'NOT_IMPLEMENTED'}
    write(folder/'validation-p6.json',result)
    print('VALIDATION='+str(folder/'validation-p6.json'),flush=True)
    print('QUALITY='+result['quality_gate']+'; P6 PHASE='+result['phase_gate'],flush=True)
    return 0 if phase else 2 if quality else 1


if __name__=='__main__':raise SystemExit(main())
