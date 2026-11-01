"""Python 3.7/3.12 loader comparison with PLY and write isolation."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

TARGET=Path(__file__).resolve().parents[1]
from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--legacy',action='store_true');args=parser.parse_args()
    folder=args.folder.resolve();folder.relative_to(TARGET/'.p6-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([folder]).install();report={}
    try:
        report['ply_calls']=install_ply_isolation(cache,'disabled') if args.legacy else []
        import angr
        binary=TARGET.parent/'EmTaint/firmware-binaries/rv130_v44/httpd'
        project=angr.Project(str(binary),auto_load_libs=False)
        main=project.loader.main_object
        segments=[]
        for index,s in enumerate(main.segments):
            data=bytes(project.loader.memory.load(s.min_addr,s.memsize))
            name='segment-'+str(index)+'.bin'
            with (folder/name).open('xb') as stream:stream.write(data)
            segments.append({'base':s.min_addr,'memsz':s.memsize,'flags':s.flags,'file':name,'sha256':hashlib.sha256(data).hexdigest()})
        report.update(python=sys.version,angr=angr.__version__,binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
            image_base=main.mapped_base,segments=segments,relocations=len(main.relocs),
            sections={s.name:[s.min_addr,s.max_addr+1] for s in main.sections if s.name},
            reads={hex(a):int.from_bytes(project.loader.memory.load(a,4),'little')
                   for a in (0xa1038,0xa1024,0x6eed0,0x6eed4,0x23f70,0x23f78)},passed=True)
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (folder/'loader.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
        guard.restore()
    print(json.dumps({k:v for k,v in report.items() if k not in ('sections','segments')}),flush=True)
    return 0 if report['passed'] and not report['violations'] else 1

if __name__=='__main__':raise SystemExit(main())
