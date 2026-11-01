"""Post-analysis identity audit of legacy synthetic call-node addresses."""
import argparse
import hashlib
import json
from pathlib import Path
import sys

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET))
from emtaint.frontends.function_store import FunctionStore
from emtaint.frontends.inputs import read_ida_cfg
from emtaint.ir.canonical import CallEffect


def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('acquisition','metadata','legacy-report','golden','folder'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    old=json.loads(args.legacy_report.read_text());source=TARGET.parent/'EmTaint/dataflow/generate_cfg.py'
    if not old['passed'] or old['violations'] or old['legacy_cfg_source_sha256']!=sha(source):raise ValueError('Missing matching actual legacy method proof')
    proof={(row['function'],row['legacy_synthetic_site'],row['name']):row for row in old['synthetic_call_sites'] if row['passed']}
    metadata={s.address:s for s in read_ida_cfg(args.metadata)};golden=json.loads(args.golden.read_text())['taint_1']
    store=FunctionStore(args.acquisition);entries=[];unresolved=[]
    for category in ('buffer_overflow','command_exec'):
        for key,value in golden[category].items():
            site=int(key,16);function=value['func'];name=value['name'];spec=metadata.get(function)
            if spec is not None and any(c.instruction==site and c.target==name for c in spec.calls):continue
            row=proof.get((function,site,name))
            if row is None:unresolved.append({'function':function,'site':site,'name':name,'reason':'No actual old synthetic-node proof'});continue
            native=row['native_instruction']
            if not any(c.instruction==native and c.target==name for c in spec.calls):raise ValueError('Native IDA call does not match legacy proof')
            module,cfg,digest=store.load(function)
            effects=[effect for block in module.functions[0].blocks for effect in block.effects
                if isinstance(effect,CallEffect) and block.id.rva+store.base==native and effect.site.point.instruction_rva+store.base==native]
            if len(effects)!=1:raise ValueError('CIR does not prove the exact call/block-address collision')
            entries.append({'function':function,'legacy_site':site,'native_site':native,'name':name,'origin':effects[0].origin,
                'cir_sha256':digest,'same_instruction':True,'validated':True,'reason':row['reason']})
    report={'entries':entries,'unresolved':unresolved,'validated':not unresolved,'legacy_probe':str(args.legacy_report),
        'legacy_probe_sha256':sha(args.legacy_report),'legacy_cfg_source_sha256':sha(source),'golden_sha256':sha(args.golden),
        'scope':'Identity-only post-analysis mapping; leaves original engine instruction addresses and Golden unchanged'}
    with (folder/'site-map.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps(report));return 0 if report['validated'] else 1


if __name__=='__main__':raise SystemExit(main())
