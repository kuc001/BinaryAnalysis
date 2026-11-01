"""Compare protected content/mtime inventories without writing those roots."""
import argparse
import hashlib
import json
from pathlib import Path
from baseline_inventory import full_inventory

TARGET=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--evidence-root',type=Path,required=True);parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--approved-baseline-root',type=Path,help='Exact separately approved new P7 archive; existing entries remain immutable')
    args=parser.parse_args();evidence=args.evidence_root.resolve();evidence.relative_to(TARGET/'.p7-work')
    folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    approved=None
    if args.approved_baseline_root:
        path=args.approved_baseline_root.resolve();approved=path.relative_to((TARGET.parent/'baselines').resolve()).as_posix()+'/'
        if not path.name.startswith('p7-'):raise ValueError('Only the explicitly approved new P7 archive may be added')
    roots={'legacy':(TARGET.parent/'EmTaint','legacy-before.json'),
        'target_venv':(TARGET/'.venv','target-venv-before.json'),
        'golden':(TARGET.parent/'baselines','golden-before.json'),
        'sealed_p6':(TARGET/'.p6-work','p6-sealed-before.json')}
    rows={}
    for name,(root,before_path) in roots.items():
        before={value['path']:value for value in json.loads((evidence/before_path).read_text(encoding='utf8'))}
        after={value['path']:value for value in full_inventory(root)}
        changed=[path for path in sorted(before) if before[path]!=after.get(path)]
        added=sorted(after.keys()-before.keys())
        permitted=[path for path in added if name=='golden' and approved is not None and path.startswith(approved)]
        unexpected=sorted(set(added)-set(permitted));unchanged=not changed and not unexpected
        rows[name]={'root':str(root.resolve()),'before_files':len(before),'after_files':len(after),'changes':changed,
            'unexpected_additions':unexpected,'approved_additions':permitted,'existing_files_unchanged':not changed,'unchanged':unchanged,
            'scope':'Existing archived content/mtime unchanged; separately approved new P7 entries listed explicitly' if permitted else 'Exact content/mtime inventory'}
        print(name+' '+str(len(after))+' unchanged='+str(unchanged),flush=True)
    planning={name:hashlib.sha256((TARGET/name).read_bytes()).hexdigest()==
        hashlib.sha256((evidence/'planning-source'/name).read_bytes()).hexdigest()
        for name in ('AGENTS.md','MIGRATION_BLUEPRINT.md','CODE_TASK.md')}
    report={'protected_roots':rows,'planning_contents_unchanged':planning,
        'producer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'passed':all(value['unchanged'] for value in rows.values()) and all(planning.values())}
    with (folder/'integrity.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
