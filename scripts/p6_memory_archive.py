"""Stream complete diagnostic arenas as existing P3 wire records, without truncation.

This is an artifact container, not a new CIR/Memory-Semantics wire schema.
Every line is accepted by the unchanged P3 codec. Counts and hashes cover all
records; the input CIR and loader bundle remain the execution replay inputs.
"""
import hashlib
import json
from emtaint.ir.canonical.wire import dumps,loads


def archive_memory(snapshot,folder):
    folder.mkdir(exist_ok=False);manifest={'schema_version':snapshot.schema_version,'groups':{}}
    for name in ('scope','architecture','budgets','assessment'):
        data=dumps(getattr(snapshot,name)).encode('utf8')
        with (folder/(name+'.json')).open('xb') as stream:stream.write(data)
        manifest[name]={'file':name+'.json','sha256':hashlib.sha256(data).hexdigest()}
    total=0
    for name in ('origin_map','objects','paths','graphs','locations','versions','reads','expressions','taint_facts','object_facts','cells'):
        digest=hashlib.sha256();size=count=0
        with (folder/(name+'.jsonl')).open('xb') as stream:
            for record in getattr(snapshot,name):
                data=(dumps(record,max_nodes=2000000,max_bytes=64*1024*1024)+'\n').encode('utf8')
                total+=len(data)
                if total>1024*1024*1024:raise ValueError('Explicit 1 GiB diagnostic archive budget exceeded')
                stream.write(data);digest.update(data);size+=len(data);count+=1
        manifest['groups'][name]={'file':name+'.jsonl','records':count,'bytes':size,'sha256':digest.hexdigest()}
    manifest['total_record_bytes']=total
    with (folder/'manifest.json').open('x',encoding='utf8') as stream:json.dump(manifest,stream,indent=2)
    return manifest


def verify_archive(folder):
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf8'))
    for name in ('scope','architecture','budgets','assessment'):
        entry=manifest[name];data=(folder/entry['file']).read_bytes()
        if hashlib.sha256(data).hexdigest()!=entry['sha256']:raise ValueError('Metadata archive hash mismatch')
        loads(data.decode('utf8'))
    for name,entry in manifest['groups'].items():
        digest=hashlib.sha256();count=size=0
        with (folder/entry['file']).open('rb') as stream:
            for line in stream:
                digest.update(line);size+=len(line);count+=1
                loads(line.decode('utf8'),max_nodes=2000000,max_bytes=64*1024*1024)
        if (digest.hexdigest(),count,size)!=(entry['sha256'],entry['records'],entry['bytes']):raise ValueError('Arena archive mismatch')
    return True
