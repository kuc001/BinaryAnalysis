"""Post-analysis Golden comparison. Never imported by the analysis engine."""
import argparse
import hashlib
import json
from pathlib import Path
TARGET=Path(__file__).resolve().parents[1]


def load(path):return json.loads(path.read_text(encoding='utf8'))


def triples(value):
    return {(int(function),int(site),target) for function,sites in value.items() for site,targets in sites.items() for target in targets}


def compare(phase,golden,icall,legacy_cg=None,site_map=None,legacy_trace=None):
    manifest=load(phase/'manifest.json') if (phase/'manifest.json').exists() else None
    known={};pending={};started=set();requirements={}
    for path in sorted(phase.glob('round-*-function-*-start.json')):started.add(load(path)['function'])
    finalized=(phase/'candidates.json').exists()
    requirement_path=phase/'requirements.json'
    if finalized and manifest is not None and requirement_path.exists():
        # A finalized phase already contains the canonical, joined sink
        # requirements and pending map.  Do not retain every diagnostic result
        # in memory: real result receipts can be multiple gigabytes each.
        for path in phase.glob('round-*-function-*-result.json'):
            address=path.name.split('-function-',1)[1].split('-result.json',1)[0]
            known[int(address,16)]=None
        pending={int(function):values for function,values in manifest.get('pending_functions',{}).items()}
        for sink in load(requirement_path)['requirements']:
            key=sink['function'],sink['site'],sink['name']
            requirements.setdefault(key,[]).append(sink)
    else:
        # An interrupted diagnostic has no aggregate evidence.  Preserve the
        # original fallback so first-divergence reports remain available.
        for path in sorted(phase.glob('round-*-function-*-result.json')):
            row=load(path);summary=row['summary'];function=summary['function'];known[function]=row
        for function,row in known.items():
            summary=row['summary']
            if summary['pending']:pending[function]=summary['pending']
            for sink in summary['sinks']:
                key=sink['function'],sink['site'],sink['name']
                requirements.setdefault(key,[]).append(sink)
    candidates=load(phase/'candidates.json') if finalized else []
    findings={}
    for row in candidates:
        evidence=row['evidence'];findings.setdefault((evidence['kind'],evidence['function'],evidence['site'],evidence['name']),[]).append(row)
    identities={}
    if site_map is not None:
        mapping=load(site_map)
        if not mapping['validated'] or mapping['golden_sha256']!=hashlib.sha256((golden/'taint.json').read_bytes()).hexdigest():raise ValueError('Site map is not validated for this Golden')
        for row in mapping['entries']:
            if not row['validated'] or not row['same_instruction']:raise ValueError('Unproven site identity')
            identities[row['function'],row['legacy_site'],row['name']]=row['native_site']
    traces={}
    if legacy_trace is not None:
        trace=load(legacy_trace)
        if trace['parser_errors'] or trace['golden_sha256']!=hashlib.sha256((golden/'taint.json').read_bytes()).hexdigest():
            raise ValueError('Trace evidence does not match the approved Golden')
        if trace['log_sha256']!=hashlib.sha256((golden/'taint.log').read_bytes()).hexdigest():
            raise ValueError('Trace evidence does not match the archived original log')
        traces={(row['function'],row['site'],row['name']):row for row in trace['rows']}
    old=load(golden/'taint.json')['taint_1'];rows=[]
    for category,key in (('copy','buffer_overflow'),('command','command_exec')):
        for site_text,expected in old[key].items():
            site=int(site_text,16);function=expected['func'];native=identities.get((function,site,expected['name']),site)
            actual=findings.get((category,function,native,expected['name']),[])
            sinks=requirements.get((function,native,expected['name']),[])
            offsets=set(row['offset'] for row in actual if row['offset'] is not None)
            expected_offsets=set(expected.get('offset',()))
            requirement_offsets={offset for sink in sinks if any(dep['kind']=='source' for dep in sink['dependencies']) for offset in sink['offsets']}
            source_present=any(dep['kind']=='source' for sink in sinks for dep in sink['dependencies'])
            if actual and expected_offsets<=offsets:status='candidate_present_evidence_review_required'
            elif not finalized:status='analysis_not_finalized'
            elif function not in known:status='function_not_completed'
            elif function in pending:status='function_incomplete'
            elif not sinks:status='sink_requirement_missing'
            elif not any(dep['kind']=='source' for sink in sinks for dep in sink['dependencies']):status='source_correspondence_unresolved'
            else:status='legacy_policy_or_extent_difference'
            trace_row=traces.get((function,site,expected['name']))
            source_comparison=None
            if trace_row is not None:
                source_rows=[]
                for source in trace_row['sources']:
                    matching=[value for value in actual if value['evidence']['source']==source]
                    actual_source_offsets={value['offset'] for value in matching if value['offset'] is not None}
                    present=bool(matching) and expected_offsets<=actual_source_offsets
                    source_rows.append({'source':source,'present_with_required_offsets':present,
                        'actual_offsets':sorted(actual_source_offsets),
                        'legacy_records':[value for value in trace_row['raw_evidence'] if value.get('source')==source],
                        'actual_evidence':[value['evidence'] for value in matching],
                        'linked_source_facts':sum(len(value.get('source_evidence_refs',())) for value in matching),
                        'review_status':'Requires constraint/guard/path review even when the source and offsets match'})
                missing=[value['source'] for value in source_rows if not value['present_with_required_offsets']]
                if actual and expected_offsets<=offsets and missing:status='candidate_source_or_offset_difference'
                source_comparison={'sources':source_rows,'missing_source_or_offsets':missing,
                    'legacy_source_missing':trace_row['missing_raw_source'],
                    'extra_source_ids':sorted({value['evidence']['source'] for value in actual}-set(trace_row['sources'])),
                    'legacy_records':trace_row['raw_evidence'],
                    'reviewed':False,'limit':'Raw old log does not record all guards, aliases or length-branch sources; no fabricated correspondence'}
            rows.append({'kind':category,'site':site,'native_site':native,'function':function,'name':expected['name'],'expected_offsets':sorted(expected_offsets),
                'actual_offsets':sorted(offsets),'status':status,'old_info':expected.get('info'),
                'diagnostic_requirement_offsets':sorted(requirement_offsets),
                'diagnostic_source_and_offset_coverage':source_present and expected_offsets<=requirement_offsets,
                'requirement_variants':len(sinks),'source_sites':sorted({dep['value'] for sink in sinks for dep in sink['dependencies'] if dep['kind']=='source'}),
                'candidate_source_sites':sorted({row['evidence']['source'] for row in actual}),
                'candidate_evidence':actual,
                'source_comparison':source_comparison,
                'pending':pending.get(function,[])})
    expected_sites={(row['kind'],row['function'],row['native_site'],row['name']) for row in rows}
    additional=[{'kind':kind,'function':function,'site':site,'name':name,'status':'additional_may_candidate_requires_explanation'}
        for kind,function,site,name in findings if (kind,function,site,name) not in expected_sites]
    old_targets=load(golden/'icall-targets.json');new_targets=load(icall/'icall-targets.json')
    expected=triples(old_targets);actual=triples(new_targets)
    empty_sites=lambda value:{(int(function),int(site)) for function,rows in value.items() for site,targets in rows.items() if not targets}
    old_empty=empty_sites(old_targets);new_empty=empty_sites(new_targets)
    cg=None
    if legacy_cg is not None:
        old_graph=load(legacy_cg)
        expected_edges={tuple(map(tuple,row)) for row in old_graph['warm_edges']}
        actual_edges={tuple(map(tuple,row)) for row in load(icall/'cg-logical-edges.json')}
        cg={'equal':expected_edges==actual_edges,'expected_edges':len(expected_edges),'actual_edges':len(actual_edges),
            'missing':sorted(expected_edges-actual_edges),'extra':sorted(actual_edges-expected_edges),
            'reference':str(legacy_cg),'reference_sha256':hashlib.sha256(legacy_cg.read_bytes()).hexdigest(),
            'scope':'Actual P6 old-environment warm CG replay; logical internal/external edges'}
    return {'gate_a':'NOT_PASSED','analysis_finished':manifest is not None,
        'analysis_complete':manifest is not None and manifest['status']=='may_fixed_point' and manifest.get('coverage','full-program')=='full-program','analysis_manifest':manifest,
        'completed_functions':len(known),'started_without_result':sorted(started-set(known)),'incomplete_functions':pending,
        'icall':{'missing':sorted(expected-actual),'extra':sorted(actual-expected),'equal':expected==actual,'entries':len(actual),
            'equality_scope':'Function/site/target candidate triples; empty unknown records are reported separately',
            'empty_sites_added':sorted(new_empty-old_empty),'empty_sites_removed':sorted(old_empty-new_empty),
            'raw_mapping_equal':old_targets==new_targets},
        'cg':cg,
        'site_identity_map':None if site_map is None else {'file':str(site_map),'sha256':hashlib.sha256(site_map.read_bytes()).hexdigest()},
        'legacy_trace_evidence':None if legacy_trace is None else {'file':str(legacy_trace),'sha256':hashlib.sha256(legacy_trace.read_bytes()).hexdigest()},
        'golden_finding_rows':rows,'additional_may_candidates':additional,
        'status_counts':{status:sum(row['status']==status for row in rows) for status in sorted({r['status'] for r in rows})},
        'diagnostic_requirement_coverage':{kind:sum(row['kind']==kind and row['diagnostic_source_and_offset_coverage'] for row in rows)
            for kind in ('copy','command')},
        'evidence_limits':{'legacy_alias_facts':'Not present as a standalone Golden artifact; use source/fixtures and trace log',
            'legacy_guard_paths':'Raw taint.log is preserved; JSON info counts are not concrete paths or solver proofs',
            'cg':'Not supplied' if cg is None else cg['scope']},
        'golden_sha256':hashlib.sha256((golden/'taint.json').read_bytes()).hexdigest(),
        'phase':str(phase),'golden':str(golden)}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('phase','golden','icall','folder'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--legacy-cg',type=Path)
    parser.add_argument('--site-map',type=Path)
    parser.add_argument('--legacy-trace',type=Path)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    report=compare(args.phase.resolve(),args.golden.resolve(),args.icall.resolve(),args.legacy_cg,args.site_map,args.legacy_trace)
    with (folder/'comparison.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
    print(json.dumps({'completed_functions':report['completed_functions'],'status_counts':report['status_counts'],'icall':report['icall'],'gate_a':report['gate_a']}))


if __name__=='__main__':main()
