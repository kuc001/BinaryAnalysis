"""Run target -i/-t from a captured source version, preserving all receipts."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import uuid

TARGET=Path(__file__).resolve().parents[1]
HELPERS=('p1_runtime.py','legacy_readonly_bootstrap.py','p7_legacy_reference.py','legacy_baseline.py','baseline_inventory.py','compare_baseline.py')


def main():
    parser=argparse.ArgumentParser(add_help=False)
    parser.add_argument('--source-root',type=Path);parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--precreated-junction',action='store_true')
    args,remaining=parser.parse_known_args();is_i=any(value in remaining for value in ('-i','--icall_check'))
    is_t=any(value in remaining for value in ('-t','--taint_check'))
    if is_i==is_t:raise ValueError('Exactly one target CLI phase is required')
    if '--output' in remaining or '--legacy-plan' in remaining:raise ValueError('This sealed launcher owns output and is APG-only')
    # Validate the logical workspace path without following an explicitly
    # prepared junction.  This permits isolated evidence to live on another
    # volume while every launcher/log path remains under BinaryAnalysis.
    folder=args.folder.absolute();folder.relative_to(TARGET/'.p7-work');execution=folder/'source'
    if is_i:
        if args.source_root is None:raise ValueError('A source root is required for a new -i run')
        source=args.source_root.resolve();source.relative_to(TARGET)
        if args.precreated_junction:
            if not folder.is_dir() or any(folder.iterdir()) or folder.resolve()==folder:
                raise ValueError('Prepared sealed folder must be an empty directory junction')
        else:folder.mkdir(exist_ok=False)
        execution.mkdir()
        manifest={}
        paths=sorted(list((source/'emtaint').rglob('*.py'))+[source/'main.py']+[source/'scripts'/name for name in HELPERS])
        for path in paths:
            relative=path.relative_to(source);data=path.read_bytes();destination=execution/relative
            destination.parent.mkdir(parents=True,exist_ok=True)
            with destination.open('xb') as stream:stream.write(data)
            manifest[relative.as_posix()]=hashlib.sha256(data).hexdigest()
        with (folder/'source-manifest.json').open('x') as stream:json.dump(manifest,stream,indent=2)
        with (folder/'launcher-source.py').open('xb') as stream:stream.write(Path(__file__).read_bytes())
    else:
        manifest=json.loads((folder/'source-manifest.json').read_text())
        if not execution.is_dir():raise ValueError('A matching sealed -i source is required')
    if not all(hashlib.sha256((execution/name).read_bytes()).hexdigest()==digest for name,digest in manifest.items()):
        raise ValueError('Sealed source changed; do not reuse it')
    output=execution/'.p7-work/cli';output.parent.mkdir(exist_ok=True)
    phase=('i-' if is_i else 't-')+uuid.uuid4().hex[:8]
    command=[sys.executable,'-B',str(execution/'main.py'),'--output',str(output)]+remaining
    with (folder/(phase+'.log')).open('x',encoding='utf8') as stream:
        process=subprocess.run(command,cwd=str(TARGET),stdout=stream,stderr=subprocess.STDOUT)
    unchanged=all(hashlib.sha256((execution/name).read_bytes()).hexdigest()==digest for name,digest in manifest.items())
    report={'command':command,'exit_code':process.returncode,'source_unchanged':unchanged,'output':str(output),
        'logical_folder':str(folder),'physical_folder':str(folder.resolve()),
        'scope':'Actual target CLI from a captured source version; Gate A requires independent evidence review'}
    with (folder/(phase+'.json')).open('x') as stream:json.dump(report,stream,indent=2)
    return process.returncode if unchanged else 1


if __name__=='__main__':raise SystemExit(main())
