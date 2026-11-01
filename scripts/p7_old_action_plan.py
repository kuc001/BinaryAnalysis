"""Prepare or execute a fresh, isolated old -t action trace inside P7 scratch.

Planning only reads the previously approved physical copy. Execution requires
explicit approval for the concrete destination recorded in the plan.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


TARGET=Path(__file__).resolve().parents[1]
MIGRATION=TARGET.parent
SOURCE=MIGRATION/'baseline-work/p7-20261029T140752Z-d85ea47a/EmTaint'
OLD_PYTHON=MIGRATION/'EmTaint/.venv/Scripts/python.exe'
SCRATCH=TARGET/'.p7-work/v8-p70-20261030T081526Z'
OMIT={'.git','.venv','__pycache__','.p0b-cache'}


def sha(path):
    digest=hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda:stream.read(1024*1024),b''):digest.update(block)
    return digest.hexdigest()


def inventory(root):
    return {str(path.relative_to(root)).replace('\\','/'):sha(path)
        for path in sorted(root.rglob('*')) if path.is_file()
        and not any(part in OMIT for part in path.relative_to(root).parts)}


def make_plan(path):
    path=path.resolve();path.relative_to(SCRATCH.resolve())
    case=SCRATCH/'p73-old-action-01'
    if case.exists() or path.exists():raise FileExistsError('P7 case or plan already exists')
    source_files=inventory(SOURCE)
    plan={'version':1,'scope':'Actual old -t observational action trace, fresh physical copy',
        'source':str(SOURCE.resolve()),'source_file_count':len(source_files),
        'source_manifest_sha256':hashlib.sha256(json.dumps(source_files,sort_keys=True).encode()).hexdigest(),
        'case':str(case.resolve()),'run_root':str((case/'run/EmTaint').resolve()),
        'capture':str((case/'capture').resolve()),'old_python':str(OLD_PYTHON.resolve()),
        'worker':str((TARGET/'scripts/p7_old_action_worker.py').resolve()),
        'worker_sha256':sha(TARGET/'scripts/p7_old_action_worker.py'),
        'archive_source':'Previously approved p7-20261029T140752Z-d85ea47a physical copy; read only',
        'write_scope':'Fresh case under BinaryAnalysis/.p7-work only; old repository, previous copy, Golden and prior results remain read only',
        'authorization':'Execution needs approval for this fresh physical copy as required by AGENTS.md section 2'}
    with path.open('x',encoding='utf8') as stream:json.dump(plan,stream,indent=2)
    return plan


def execute(path):
    path=path.resolve();path.relative_to(SCRATCH.resolve())
    plan=json.loads(path.read_text(encoding='utf8'))
    if plan.get('version')!=1 or Path(plan['source']).resolve()!=SOURCE.resolve():raise ValueError('Plan identity')
    case=Path(plan['case']).resolve();case.relative_to(SCRATCH.resolve())
    run=Path(plan['run_root']).resolve();capture=Path(plan['capture']).resolve()
    if run!=case/'run/EmTaint' or capture!=case/'capture':raise ValueError('Destination identity')
    if case.exists():raise FileExistsError('Fresh P7 case already exists')
    if sha(Path(plan['worker']))!=plan['worker_sha256']:raise ValueError('Worker changed after plan')
    before=inventory(SOURCE)
    if len(before)!=plan['source_file_count'] or hashlib.sha256(json.dumps(before,sort_keys=True).encode()).hexdigest()!=plan['source_manifest_sha256']:
        raise ValueError('Approved source changed after plan')
    case.mkdir();run.parent.mkdir()
    shutil.copytree(SOURCE,run,ignore=shutil.ignore_patterns(*OMIT))
    copied=inventory(run)
    if copied!=before:raise RuntimeError('Physical copy hash mismatch')
    for name in before:
        if os.path.samefile(SOURCE/name,run/name) or (run/name).stat().st_nlink!=1:
            raise RuntimeError('Copy is not physically independent: '+name)
    with (case/'copy-manifest.json').open('x',encoding='utf8') as stream:json.dump(before,stream,indent=2)
    env=os.environ.copy();env['PYTHONDONTWRITEBYTECODE']='1'
    env.pop('PYTHONPATH',None);env.pop('VIRTUAL_ENV',None)
    command=[str(OLD_PYTHON),'-B',plan['worker'],'--run-root',str(run),'--capture',str(capture)]
    with (case/'stdout.log').open('x',encoding='utf8') as stdout,(case/'stderr.log').open('x',encoding='utf8') as stderr:
        result=subprocess.run(command,cwd=run,env=env,stdout=stdout,stderr=stderr,timeout=600)
    after=inventory(SOURCE)
    report={'command':command,'exit_code':result.returncode,'source_unchanged':before==after,
        'copy_file_count':len(copied),'capture':str(capture)}
    with (case/'execution.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps(report,indent=2))
    return 0 if result.returncode==0 and before==after else 1


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if args.execute:return execute(args.plan)
    print(json.dumps(make_plan(args.plan),indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
