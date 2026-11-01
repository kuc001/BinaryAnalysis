"""Real legacy CLI delegation into a new physical RunRoot.

Plan generation only writes inside P7. Executing the plan creates new
baseline-work/baselines directories and requires the separate authorization
specified by AGENTS.md. Existing Golden and RunRoots are never reused.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

TARGET=Path(__file__).resolve().parents[1]
MIGRATION=TARGET.parent
sys.path.insert(0,str(TARGET/'scripts'))
import legacy_baseline as baseline
from p1_runtime import ProbeWriteGuard


def read(path):return json.loads(Path(path).read_text(encoding='utf8'))


def isolation_reference():
    digest=baseline.sha(TARGET/'scripts/legacy_readonly_bootstrap.py')
    for path in sorted((MIGRATION/'baselines/rv130_1_0_3_44').glob('*/isolation-proof.json')):
        proof=read(path)
        if proof.get('verified') and proof.get('contract_equal') and proof.get('bootstrap_sha256')==digest:
            return path
    raise ValueError('No validated isolation proof matches the current bootstrap')


def plan_for(output):
    output=Path(output).resolve();output.relative_to(TARGET/'.p7-work')
    token='p7-'+datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')+'-'+uuid.uuid4().hex[:8]
    return {'version':1,'engine':'legacy-python-reference','memory_engine':'legacy',
        'output':str(output),'run_root':str(MIGRATION/'baseline-work'/token/'EmTaint'),
        'archive_root':str(MIGRATION/'baselines/rv130_1_0_3_44'/token),
        'binary_sha256':baseline.sha(baseline.LEGACY/baseline.REL_BINARY),
        'bootstrap_sha256':baseline.sha(TARGET/'scripts/legacy_readonly_bootstrap.py'),
        'isolation_reference':str(isolation_reference()),
        'authorization':'Execution requires separate approval for these new physical RunRoot/archive paths; plan generation is read-only outside P7',
        'semantics':'Original old FastSearch/AccurateDataFlow/Claripy Load-Store; no APG/Gate M claim; warm legacy IDA input is archived'}


def validate_plan(plan,output,stage):
    if plan.get('version')!=1 or plan.get('memory_engine')!='legacy':raise ValueError('Unsupported legacy plan')
    output=Path(output).resolve();output.relative_to(TARGET/'.p7-work')
    if Path(plan['output']).resolve()!=output:raise ValueError('Plan output mismatch')
    run=Path(plan['run_root']).resolve();archive=Path(plan['archive_root']).resolve()
    run.relative_to(MIGRATION/'baseline-work');archive.relative_to(MIGRATION/'baselines/rv130_1_0_3_44')
    if run.name!='EmTaint' or not run.parent.name.startswith('p7-') or archive.name!=run.parent.name:raise ValueError('P7 RunRoot/archive identity mismatch')
    if stage=='icall' and (run.exists() or archive.exists()):raise FileExistsError('Legacy reference requires fresh physical directories')
    if plan['binary_sha256']!=baseline.sha(baseline.LEGACY/baseline.REL_BINARY):raise ValueError('Legacy binary changed since planning')
    if plan['bootstrap_sha256']!=baseline.sha(TARGET/'scripts/legacy_readonly_bootstrap.py'):raise ValueError('Bootstrap changed since planning')
    return run,archive


def verify_prepared(run,archive,folder,before,plan):
    """Resume only an intact physical copy stopped before parser/main ran."""
    if any((folder/name).exists() for name in ('legacy-state.json','icall.json','taint.json')):
        raise ValueError('Prepared resume cannot reuse a started analysis')
    if any((archive/name).exists() for name in ('parser.bootstrap.json','icall.log','taint.log','icall.command.json','taint.command.json')):
        raise ValueError('Prepared resume is limited to failure before parser/main execution')
    if (run/'.p0b-cache').exists():raise ValueError('Prepared resume requires an untouched parser cache')
    if read(archive/'file-inventory-before.json')!=before:raise ValueError('Legacy changed after the prepared copy')
    original=read(archive/'plan.json')
    for name in ('run_root','archive_root','output','binary_sha256','bootstrap_sha256'):
        if original[name]!=plan[name]:raise ValueError('Prepared plan identity changed: '+name)
    expected={record['path']:record for record in before if not any(part in baseline.EXCLUDE for part in Path(record['path']).parts)}
    actual={record['path']:record for record in baseline.inventory(run)}
    if set(actual)!=set(expected)|{'_p0b_bootstrap.py'}:raise ValueError('Prepared copy file set changed')
    for relative,record in expected.items():
        if actual[relative]!=record or os.path.samefile(baseline.LEGACY/relative,run/relative) or (run/relative).stat().st_nlink!=1:
            raise ValueError('Prepared physical copy changed: '+relative)
    if baseline.sha(run/'_p0b_bootstrap.py')!=plan['bootstrap_sha256']:raise ValueError('Prepared bootstrap changed')
    for relative,name in ((baseline.REL_RESULT,'preexisting.json'),(baseline.REL_META/'httpd_icall.json','preexisting-icall-targets.json')):
        if baseline.sha(run/relative)!=baseline.sha(archive/name):raise ValueError('Prepared input differs from preexisting snapshot')
    baseline.validate_run_root(run)
    return len(expected)


def execute(args,folder):
    """Called only for an explicitly selected, separately approved legacy plan."""
    plan_path=Path(args.legacy_plan).resolve();plan_path.relative_to(TARGET/'.p7-work')
    plan=read(plan_path);stage='icall' if args.icall_check else 'taint'
    resume=getattr(args,'legacy_resume_prepared',False)
    if resume and stage!='icall':raise ValueError('Prepared resume is an icall-only operation')
    run,archive=validate_plan(plan,folder,'prepared' if resume else stage)
    if baseline.sha(Path(args.binary_file))!=plan['binary_sha256'] or args.firmware_name!='rv130' or args.firmware_version!='1_0_3_44':
        raise ValueError('Legacy reference is limited to the audited rv130 firmware')
    guard=ProbeWriteGuard([folder,run.parent,archive]).install()
    try:
        proof=read(plan['isolation_reference']);baseline.require_isolation(proof)
        before=baseline.inventory(baseline.LEGACY);status=baseline.git(baseline.LEGACY,'status','--porcelain=v1','--untracked-files=all')
        if stage=='icall':
            if resume:
                copied=verify_prepared(run,archive,folder,before,plan)
                baseline.write_json(archive/'prepared-resume-plan.json',plan)
            else:
                archive.mkdir(parents=True,exist_ok=False)
                baseline.write_json(archive/'file-inventory-before.json',before)
                baseline.write_json(archive/'plan.json',plan)
                copied=baseline.copy_run(run,before);baseline.copy_bootstrap(run)
                shutil.copy2(run/baseline.REL_RESULT,archive/'preexisting.json')
                shutil.copy2(run/baseline.REL_META/'httpd_icall.json',archive/'preexisting-icall-targets.json')
            command=baseline.bootstrap_command(run,archive,archive/'parser.bootstrap.json','probe')
            process=subprocess.run(command,cwd=run,env=baseline.child_environment(),capture_output=True,timeout=300)
            with (archive/'parser.stdout.txt').open('xb') as stream:stream.write(process.stdout)
            with (archive/'parser.stderr.txt').open('xb') as stream:stream.write(process.stderr)
            if process.returncode or read(archive/'parser.bootstrap.json')['violations']:raise RuntimeError('Legacy parser isolation probe failed')
            value=json.loads(process.stdout)
            if value['contract']!=proof['contract']:raise RuntimeError('Actual legacy parser contract differs from validated isolation reference')
            baseline.write_json(archive/'isolation-proof.json',proof)
            baseline.write_json(archive/'environment.json',value['environment'])
            baseline.write_json(folder/'legacy-state.json',{'plan_sha256':baseline.sha(plan_path),'archive':str(archive),'run_root':str(run),'copied_files':copied})
            baseline.verify_legacy_step(before,status,archive,'parser')
        else:
            state=read(folder/'legacy-state.json')
            if state['plan_sha256']!=baseline.sha(plan_path):raise ValueError('Legacy -i/-t plan changed')
            baseline.validate_run_root(run)
            if read(folder/'icall.json')['memory_engine']!='legacy':raise ValueError('A matching legacy -i is required')
            proof=read(archive/'isolation-proof.json')
        record=baseline.run_stage(run,archive,stage,False,1800,proof)
        baseline.verify_legacy_step(before,status,archive,stage)
        shutil.copy2(archive/(stage+'.json'),folder/('legacy-'+stage+'.json'))
        if stage=='icall':shutil.copy2(archive/'icall-targets.json',folder/'icall-targets.json')
        manifest={'phase':stage,'engine':'legacy-python-reference','memory_engine':'legacy','status':'legacy_reference_complete',
            'binary_sha256':plan['binary_sha256'],'legacy_interpreter':str(baseline.OLD_PYTHON),
            'run_root':str(run),'archive':str(archive),'stage_command':record,'violations':guard.violations,
            'gate_a':'NOT_EVALUATED; this reference does not validate the APG engine'}
        baseline.write_json(folder/(stage+'.json'),manifest)
        print(json.dumps(manifest));return 0
    finally:guard.restore()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,required=True);parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    plan=plan_for(args.output);validate_plan(plan,args.output,'icall');baseline.write_json(folder/'plan.json',plan)
    print(json.dumps(plan,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
