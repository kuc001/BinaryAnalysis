"""Snapshot target source before a controlled native replay; never clone legacy."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys

TARGET=Path(__file__).resolve().parents[1]
HELPERS=('p1_runtime.py','legacy_readonly_bootstrap.py','p7_legacy_reference.py','legacy_baseline.py','baseline_inventory.py','compare_baseline.py')


def main():
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source-root',type=Path,required=True);parser.add_argument('--folder',type=Path,required=True)
    args,remaining=parser.parse_known_args();source=args.source_root.resolve();source.relative_to(TARGET)
    folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    execution=folder/'source';execution.mkdir()
    paths=sorted(list((source/'emtaint').rglob('*.py'))+[source/'main.py']+[source/'scripts'/name for name in HELPERS])
    manifest={}
    for path in paths:
        relative=path.relative_to(source);data=path.read_bytes();destination=execution/relative
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open('xb') as stream:stream.write(data)
        manifest[relative.as_posix()]=hashlib.sha256(data).hexdigest()
    runner=TARGET/'scripts/p7_function_replay.py';runner_data=runner.read_bytes()
    for name,path in (('launcher-source.py',Path(__file__)),('runner-source.py',runner),('codec-source.py',TARGET/'scripts/p7_replay_codec.py')):
        with (folder/name).open('xb') as stream:stream.write(path.read_bytes())
    with (folder/'source-manifest.json').open('x') as stream:json.dump(manifest,stream,indent=2)
    command=[sys.executable,'-B',str(runner),'--source-root',str(execution),'--folder',str(folder/'analysis')]+remaining
    with (folder/'replay.log').open('x',encoding='utf8') as stream:
        process=subprocess.run(command,cwd=str(TARGET),stdout=stream,stderr=subprocess.STDOUT)
    unchanged=all(hashlib.sha256((execution/name).read_bytes()).hexdigest()==digest for name,digest in manifest.items())
    context_path=folder/'analysis/context.json';context=json.loads(context_path.read_text()) if context_path.exists() else {}
    runner_matches=context.get('runner_sha256')==hashlib.sha256(runner_data).hexdigest()
    report={'input_source':str(source),'execution_source':str(execution),'command':command,'exit_code':process.returncode,
        'execution_source_unchanged':unchanged,'runner_matches_archived_source':runner_matches,
        'scope':'Controlled function replay with sealed target source; not full-program Gate A'}
    with (folder/'sealed-replay.json').open('x') as stream:json.dump(report,stream,indent=2)
    return 0 if process.returncode==0 and unchanged and runner_matches else 1


if __name__=='__main__':raise SystemExit(main())
