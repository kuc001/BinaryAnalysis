"""Read-only aggregation; per-invocation/scoped counts are never session unique."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path

TARGET=Path(__file__).resolve().parents[1]


def summarize(phase,legacy_metrics):
    totals=Counter();maxima=Counter();calls=Counter();steps=0;seconds=0;functions=set();rounds=Counter();rows=0
    for path in sorted(phase.glob('round-*-function-*-result.json')):
        value=json.loads(path.read_text(encoding='utf8'));rows+=1
        invocation=value['invocation'];functions.add(invocation['function']);rounds[invocation['round']]+=1
        steps+=invocation['steps'];seconds+=invocation['wall_seconds']
        for key,number in value['metrics'].items():
            if type(number) is int:totals[key]+=number;maxima[key]=max(maxima[key],number)
        calls.update(value['metrics'].get('memory_port_calls',{}))
    manifest=json.loads((phase/'manifest.json').read_text()) if (phase/'manifest.json').exists() else None
    old=json.loads(legacy_metrics.read_text(encoding='utf8'))
    return {'phase':str(phase),'completed_invocations':rows,'functions_observed':len(functions),'round_invocations':dict(rounds),
        'new_metrics':{'sum_per_invocation':dict(totals),'max_per_invocation':dict(maxima),'memory_port_calls':dict(calls),
            'taint_demand_steps_sum':steps,'function_analysis_seconds_sum':seconds,'summary_invocations':rows,
            'smt_queries_in_this_taint_path':0,'smt_scope':'Abstract may propagation; independent solver conformance probes are separate',
            'scope':'Distinct function/reanalysis arenas; sums include repeated analysis and are not session-unique counts'},
        'legacy_observation':{'source':str(legacy_metrics),'sha256':hashlib.sha256(legacy_metrics.read_bytes()).hexdigest(),
            'scope':old['scope'],'expression_maxima':{kind:row['maxima'] for kind,row in old['expressions'].items()},
            'counts':old['counts'],'raw_smt_checks':old['raw_smt_checks'],'frontend_status_counts':old['frontend_status_counts'],
            'triggered_gates':[g for g in old['gates'] if g['hits']]},
        'manifest':manifest,'complete_run':manifest is not None,
        'comparison_limit':'Old per-root observed expression maxima and new per-function DAG totals have different denominators; no speedup/size-reduction claim',
        'peak_rss':'Read the matching CLI command receipt; null while the process is running'}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('phase','legacy-metrics','folder'):parser.add_argument('--'+name,type=Path,required=True)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    report=summarize(args.phase.resolve(),args.legacy_metrics.resolve())
    with (folder/'metrics.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps({key:report[key] for key in ('completed_invocations','functions_observed','round_invocations','complete_run')}))


if __name__=='__main__':raise SystemExit(main())
