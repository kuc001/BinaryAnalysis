"""Target-only isolated per-function acquisition of the complete IDA universe."""
import argparse
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import traceback
TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET))
from p1_runtime import ProbeWriteGuard


def write(path,data):
    with path.open('x',encoding='utf8') as stream:json.dump(data,stream,indent=2)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--functions',nargs='+',type=lambda x:int(x,0))
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for key in ('TEMP','TMP','TMPDIR'):os.environ[key]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([folder]).install();report={};started=time.monotonic()
    try:
        from emtaint.frontends.ida_vex import IdaVexFrontend
        from emtaint.frontends.inputs import read_ida_cfg
        from emtaint.frontends.loader_image import relocated_image
        from emtaint.ir.canonical.wire import dumps
        binary=TARGET.parent/'EmTaint/firmware-binaries/rv130_v44/httpd'
        metadata=TARGET.parent/'EmTaint/data/ida_data/rv130_1_0_3_44/httpd_cfg.json'
        specs=read_ida_cfg(metadata);specs=tuple(s for s in specs if args.functions is None or s.address in args.functions)
        frontend=IdaVexFrontend(binary);segments,loader=relocated_image(binary)
        for i,(base,data,memsz,flags) in enumerate(segments):
            with (folder/('segment-'+str(i)+'.bin')).open('xb') as stream:stream.write(data)
            loader['segments'][i]['file']='segment-'+str(i)+'.bin'
        write(folder/'loader.json',loader);rows=[]
        for spec in specs:
            tick=time.monotonic();result=frontend.lift((spec,));module=result.module;function=module.functions[0]
            output=folder/('function-'+hex(spec.address));output.mkdir()
            data=dumps(function,max_nodes=8000000,max_bytes=256*1024*1024).encode('utf8')
            with (output/'function.json').open('xb') as stream:stream.write(data)
            with (output/'origins.jsonl').open('x',encoding='utf8') as stream:
                for origin in module.origin_map:stream.write(dumps(origin)+'\n')
            provenance = result.provenance
            source_hints = () if provenance is None else provenance.source_hints
            instruction_hints = () if provenance is None else provenance.instruction_hints
            source_text = ''.join(json.dumps(asdict(item), sort_keys=True) + chr(10) for item in source_hints)
            instruction_text = ''.join(json.dumps(asdict(item), sort_keys=True) + chr(10) for item in instruction_hints)
            for filename, content in (('debug-provenance.jsonl', source_text), ('debug-instructions.jsonl', instruction_text)):
                with (output/filename).open('x', encoding='utf8') as stream:stream.write(content)
            source_sha = hashlib.sha256(source_text.encode('utf8')).hexdigest()
            instruction_sha = hashlib.sha256(instruction_text.encode('utf8')).hexdigest()
            for name,value in (('architecture',module.architecture),('producer',module.producer),('assessment',module.assessment)):
                with (output/(name+'.json')).open('x',encoding='utf8') as stream:stream.write(dumps(value,max_nodes=8000000,max_bytes=256*1024*1024))
            diagnostics=result.report();diagnostics['cfgs']=[{'edges':[(e.source.token,e.target.token,e.kind.value,e.label) for e in cfg.edges]} for cfg in result.cfgs()]
            write(output/'frontend.json',diagnostics)
            rows.append({'function':spec.address,'directory':output.name,'blocks':len(function.blocks),
                'source_blocks':len(spec.blocks),'cir_sha256':hashlib.sha256(data).hexdigest(),
                'debug_provenance_sha256':source_sha,'debug_instruction_sha256':instruction_sha,
                'debug_provenance_records':len(source_hints),'debug_instruction_records':len(instruction_hints),
                'unsupported':module.assessment.unsupported_ops,'wall_seconds':time.monotonic()-tick})
            if len(rows)%25==0:print('ACQUIRED='+str(len(rows))+'/'+str(len(specs)),flush=True)
        report.update(functions=len(rows),rows=rows,binary_sha256=frontend.image.sha256,
            metadata_sha256=hashlib.sha256(metadata.read_bytes()).hexdigest(),passed=len(rows)==len(specs))
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations;report['wall_seconds']=time.monotonic()-started
        write(folder/'acquisition-report.json',report);guard.restore()
    print(json.dumps({k:v for k,v in report.items() if k!='rows'}),flush=True)
    return 0 if report.get('passed') and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
