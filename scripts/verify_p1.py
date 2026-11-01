"""Independently review fresh P1 9.3.4 evidence without changing raw reports."""
import argparse
import json
from pathlib import Path


def verify(root):
    def read(relative):
        return json.loads((root / relative).read_text(encoding='utf8'))
    manifest = read('manifest.json')
    assert manifest['status'] == 'probed'
    assert manifest['legacy_git_unchanged']
    assert all(r['unchanged'] for r in manifest['integrity'].values())
    for label in ('legacy', 'target-venv', 'golden'):
        assert read(label + '-before.json') == read(label + '-after.json')
    expected_cases = {'expressions', 'memory-markers', 'sat', 'unsat', 'z3-direct', 'z3-preload', 'timeout', 'backend-status'}
    assert {(r['environment'], r['case']) for r in manifest['probes']} == {
        (label, case) for label in ('legacy', 'target') for case in expected_cases}
    assert len(manifest['probes']) == 16
    reports = {}
    for item in manifest['probes']:
        label, case = item['environment'], item['case']
        assert item['exit_code'] == 0 and not item['timed_out']
        report = read(label + '/' + case + '/report.json')
        assert report['ok'] and not report['violations']
        reports[label, case] = report['result']
    for field in ('adapter_contract', 'concrete', 'replacement_variables', 'bits', 'same_hash', 'variables'):
        assert reports['legacy', 'expressions'][field] == reports['target', 'expressions'][field], field
    for label in ('legacy', 'target'):
        for case in ('sat', 'z3-preload'):
            value = reports[label, case]
            assert value['sat'] is True and value['values'] == [7] and value['min'] == value['max'] == 7
        assert reports[label, 'unsat']['sat'] is False
        assert reports[label, 'z3-direct'] == {'status': 'sat', 'value': 7}
        timeout = reports[label, 'timeout']
        assert any(c['status'] == 'unknown' and c['reason'] == 'timeout' for c in timeout['raw_checks'])
    assert reports['legacy', 'timeout']['frontend_boolean'] is False
    assert reports['target', 'timeout']['error_type'] == 'ClaripySolverInterruptError'
    assert reports['target', 'memory-markers']['status'] == 'UNSUPPORTED'
    for op in ('Load', 'Store'):
        value = reports['legacy', 'memory-markers'][op]
        assert (value['args_count'], value['address_bits'], value['bits']) == (1, 32, 16)
        assert value['error_type'] == 'ClaripyFrontendError' and value['error'] == 'Backend error during solve'
    old, new = (reports[label, 'backend-status']['cases'] for label in ('legacy', 'target'))
    assert old['unknown']['boolean'] is False and old['timeout']['boolean'] is False
    assert new['unknown']['error_type'] == 'ClaripyZ3Error'
    assert new['timeout']['error_type'] == 'ClaripySolverInterruptError'
    assert all(c['raw_check_calls'] == 1 for c in old.values())
    assert all(c['raw_check_calls'] == 1 for c in new.values())
    native = read('native-conformance/report.json')
    injection = read('adapter-status-injection/report.json')
    assert native['gate'] == injection['gate'] == 'PASS'
    assert len(native['cases']) == 16 and all(c['passed'] for c in native['cases'])
    assert len(injection['cases']) == 3 and all(c['passed'] for c in injection['cases'])
    assert not injection['violations']
    summary = {'gate': 'PASS', 'scope': 'P1 pure BV/API only; no P3/P5 memory or target E2E claim',
               'probes': 16, 'native_port_cases': 16, 'adapter_fault_injection_cases': 3,
               'integrity': manifest['integrity'], 'expression_normalization_equal': True,
               'native_timeout': native['cases'][-1]['result'],
               'legacy_timeout_false_is_not_unsat': True}
    with (root / 'validation-p1.json').open('x', encoding='utf8') as f:
        json.dump(summary, f, indent=2)
    return summary


if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence', type=Path)
    print(json.dumps(verify(p.parse_args().evidence.resolve())))
