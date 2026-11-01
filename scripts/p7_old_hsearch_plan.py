"""Prepare the separate approval plan for one physical old hsearch -t run."""
import argparse
import hashlib
import json
from pathlib import Path

from p7_old_action_plan import SOURCE,OLD_PYTHON,SCRATCH,TARGET,inventory,sha


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--plan',type=Path,required=True)
    args=parser.parse_args();path=args.plan.resolve();path.relative_to(SCRATCH.resolve())
    case=SCRATCH/'p74-old-hsearch-01'
    if case.exists() or path.exists():raise FileExistsError('P7 hsearch case or plan exists')
    files=inventory(SOURCE);worker=TARGET/'scripts/p7_old_hsearch_worker.py'
    plan={'version':1,'scope':'Actual old -t hsearch_r FIND observational trace, fresh physical copy',
        'source':str(SOURCE.resolve()),'source_file_count':len(files),
        'source_manifest_sha256':hashlib.sha256(json.dumps(files,sort_keys=True).encode()).hexdigest(),
        'case':str(case.resolve()),'run_root':str((case/'run/EmTaint').resolve()),
        'capture':str((case/'capture').resolve()),'old_python':str(OLD_PYTHON.resolve()),
        'worker':str(worker.resolve()),'worker_sha256':sha(worker),
        'archive_source':'Previously approved p7-20261029T140752Z-d85ea47a physical copy; read only',
        'write_scope':'Fresh case under BinaryAnalysis/.p7-work only; old repository, prior copies, Golden and results read only',
        'authorization':'Execution needs separate approval under AGENTS.md section 2'}
    with path.open('x',encoding='utf8') as stream:json.dump(plan,stream,indent=2)
    print(json.dumps(plan,indent=2));return 0


if __name__=='__main__':raise SystemExit(main())
