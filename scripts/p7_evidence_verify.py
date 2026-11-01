"""Independent P3 replay of archived P7 source evidence, with no analysis writes."""
import argparse
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import sys

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET))
from emtaint.ir.canonical.wire import loads,schema_documents
from emtaint.memory.state import MemorySnapshot
from emtaint.memory.engine import PythonMemoryEngine
from emtaint.results.memory_archive import verify_archive


def replay(folder):
    manifest=json.loads((folder/'manifest.json').read_text(encoding='utf8'))
    fields={}
    for name in ('scope','architecture','budgets','assessment'):
        entry=manifest[name];path=(folder/entry['file']).resolve();path.relative_to(folder.resolve())
        fields[name]=loads(path.read_text(encoding='utf8'))
    for name,entry in manifest['groups'].items():
        path=(folder/entry['file']).resolve();path.relative_to(folder.resolve())
        with path.open(encoding='utf8') as stream:
            fields[name]=tuple(loads(line,max_nodes=2000000,max_bytes=64*1024*1024) for line in stream)
    verify_archive(folder)
    snapshot=MemorySnapshot(**fields,schema_version=manifest['schema_version'])
    restored=PythonMemoryEngine.from_snapshot(snapshot)
    return {'archive':str(folder),'manifest_sha256':hashlib.sha256((folder/'manifest.json').read_bytes()).hexdigest(),
        'function_rva':snapshot.scope.function.rva,'facts':len(snapshot.taint_facts),'metrics':restored.metrics(),
        'reference_closed':True,'p3_wire_replay':True,'same_facts':tuple(restored.facts)==snapshot.taint_facts}


def verify_source_links(phase,index_path,candidates_path=None):
    """Verify actual archived facts behind the compact candidate source index.

    This checks source binding receipts, not the whole source-to-sink proof.
    It intentionally cannot turn an unproved may path into a confirmation.
    """
    phase=phase.resolve();index_path=index_path.resolve();index_path.relative_to(phase)
    index=json.loads(index_path.read_text(encoding='utf8'));digest=hashlib.sha256(index_path.read_bytes()).hexdigest()
    facts={};receipts={};bindings=0
    for source,records in index.items():
        source=int(source)
        for record in records:
            if record['source_site']!=source or record['binding']['source_site']!=source:raise ValueError('Source index identity mismatch')
            archive=Path(record['archive']).resolve();archive.relative_to(phase)
            manifest_path=archive/'manifest.json'
            if hashlib.sha256(manifest_path.read_bytes()).hexdigest()!=record['manifest_sha256']:raise ValueError('Source archive hash mismatch')
            if archive not in facts:
                verify_archive(archive);manifest=json.loads(manifest_path.read_text(encoding='utf8'))
                group=(archive/manifest['groups']['taint_facts']['file']).resolve();group.relative_to(archive)
                facts[archive]={}
                with group.open(encoding='utf8') as stream:
                    for line in stream:
                        fact=loads(line,max_nodes=2000000,max_bytes=64*1024*1024)
                        facts[archive][fact.id]=json.loads(json.dumps(asdict(fact),default=str))
            if facts[archive].get(record['fact_id'])!=record['binding']['fact']:raise ValueError('Source binding does not match the archived P3 fact')
            receipt=Path(record['receipt']).resolve();receipt.relative_to(phase)
            if receipt not in receipts:receipts[receipt]=json.loads(receipt.read_text(encoding='utf8'))
            actual=receipts[receipt]
            if record not in actual.get('source_bindings',()):raise ValueError('Source binding is missing from the actual invocation receipt')
            if actual['source_memory_evidence']['manifest_sha256']!=record['manifest_sha256']:raise ValueError('Receipt source archive differs')
            bindings+=1
    candidates=0
    if candidates_path is not None:
        candidates_path=candidates_path.resolve();candidates_path.relative_to(phase)
        for candidate in json.loads(candidates_path.read_text(encoding='utf8')):
            source=candidate['evidence']['source'];refs=candidate.get('source_evidence_refs',())
            if not refs:raise ValueError('Known candidate Source has no archived binding reference')
            for ref in refs:
                if Path(ref['index']).resolve()!=index_path or ref['sha256']!=digest:raise ValueError('Candidate source index differs')
                if ref['source_site']!=source or ref['bindings']!=len(index.get(str(source),())) or not ref['bindings']:
                    raise ValueError('Candidate source binding identity/count mismatch')
            candidates+=1
    return {'index_sha256':digest,'source_sites':sorted(int(source) for source in index),'bindings':bindings,
        'archives':len(facts),'receipts':len(receipts),'linked_candidates':candidates,'passed':True,
        'scope':'Actual P3 source facts and invocation receipts; does not prove full caller projection or sink feasibility'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--input',type=Path,required=True);parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--source-index',type=Path);parser.add_argument('--candidates',type=Path)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    rows=[];errors=[]
    for manifest in sorted(args.input.resolve().rglob('*-source-memory/manifest.json')):
        try:rows.append(replay(manifest.parent))
        except Exception as error:errors.append({'archive':str(manifest.parent),'error':type(error).__name__+': '+str(error)})
    schemas={name:json.loads((TARGET/'docs/migration/schemas'/name).read_text())==schema for name,schema in schema_documents().items()}
    report={'archives':rows,'errors':errors,'unchanged_schemas':schemas,'passed':bool(rows) and not errors and all(schemas.values())}
    if args.candidates and not args.source_index:raise ValueError('Candidate verification requires its source index')
    if args.source_index:
        try:report['source_links']=verify_source_links(args.input,args.source_index,args.candidates)
        except Exception as error:
            report['source_links']={'passed':False,'error':type(error).__name__+': '+str(error)};report['passed']=False
    with (folder/'report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps({'archives':len(rows),'facts':sum(row['facts'] for row in rows),'errors':errors,'passed':report['passed']}))
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
