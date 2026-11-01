"""Pair one real old Load Action with the sealed P7 memory definition trace."""
import argparse
import json
from pathlib import Path


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--old',type=Path,required=True)
    parser.add_argument('--new',type=Path,required=True)
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    old=json.loads(args.old.read_text(encoding='utf8'))
    new=json.loads(args.new.read_text(encoding='utf8'))
    actions=[row for row in old['actions'] if row['instruction']==0x4e4e0 and row['type']=='wl']
    if len(actions)!=1:raise ValueError('Expected one real old Load Action at 0x4e4e0')
    load=actions[0]
    traces=[row for row in new['memory_origin_trace'] if row['load_origin']=='f46330:o849']
    selected=[row for row in traces if row['stage']=='select']
    resolved=[row for row in traces if row['stage']=='result']
    if len(selected)!=1 or len(resolved)!=1:raise ValueError('Expected one target memory definition trace')
    selection,result=selected[0],resolved[0]
    concrete={row['concrete'] for row in result['alternatives'] if type(row['concrete']) is int}
    old_address=load['addr_value'];old_value=int(load['value'])
    offset=selection['location']['offset_lower']
    same_address=old_address==(0x7fffffff+offset)%(1<<32)
    same_value=old_value in concrete
    aliases={row['origin']:row['alias'] for row in selection['stores']}
    expected_aliases={'f46330:o750':'may_alias','f46330:o826':'may_alias',
        'f46330:o294':'must_alias'}
    arenas=new['memory_origin_arenas']
    read_versions=sorted({row['state'].rsplit("key='",1)[-1].split("'",1)[0]
        for row in arenas['reads']})
    evidence={'scope':'Real old -t local Load paired with identical target CIR/summary replay; not cross-function Source proof',
        'old':{'block':load['block'],'statement':load['statement'],'instruction':load['instruction'],
            'address':old_address,'value':old_value,'address_alias':load['src_alias']},
        'new':{'origin':'f46330:o849','offset':offset,'width_bits':selection['location']['width_bits'],
            'candidate_aliases':aliases,'concrete_values':sorted(concrete),
            'apg_paths':arenas['paths'],'read_versions':read_versions,
            'local_source_facts':len(new['source_facts']),
            'sink_offsets':sorted({value for sink in new['summary']['sinks']
                if sink['site']==0x4e504 for value in sink['offsets']})},
        'checks':{'same_address':same_address,'old_value_retained':same_value,
            'candidate_aliases':aliases==expected_aliases,
            'versions':read_versions==['mem-0','mem-1'],
            'apg_path':bool(arenas['paths'])},
        'remaining':'Caller Source/TaintFact and two open-tail MayAlias alternatives are not locally proven'}
    evidence['passed']=all(evidence['checks'].values())
    if not evidence['passed']:raise AssertionError(evidence['checks'])
    with args.output.open('x',encoding='utf8') as stream:json.dump(evidence,stream,indent=2)
    print(json.dumps({'passed':evidence['passed'],'checks':evidence['checks']}))
    return 0


if __name__=='__main__':raise SystemExit(main())
