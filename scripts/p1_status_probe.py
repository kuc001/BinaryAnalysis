"""Target-only UNKNOWN fault injection through the real ClaripyAdapter/backend."""
import argparse
import json
from pathlib import Path
import sys
import os
import tempfile

TARGET = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TARGET))
from p1_runtime import ProbeWriteGuard
from emtaint.solver.backends.claripy_adapter import ClaripyAdapter
from emtaint.solver.port import SolverQuery, Term


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence', type=Path)
    root = p.parse_args().evidence.resolve()
    root.relative_to(TARGET / '.p1-work')
    folder = root / 'adapter-status-injection'
    folder.mkdir(exist_ok=False)
    cache = folder / 'cache'
    cache.mkdir()
    for key in ('TEMP', 'TMP', 'TMPDIR'):
        os.environ[key] = str(cache)
    tempfile.tempdir = str(cache)
    guard = ProbeWriteGuard([folder]).install()
    rows = []
    try:
        adapter = ClaripyAdapter()
        import z3
        original_check, original_reason = z3.Solver.check, z3.Solver.reason_unknown
        for reason, expected in [('incomplete', 'UNKNOWN'), ('timeout', 'TIMEOUT'),
                                 ('max. resource limit exceeded', 'UNKNOWN')]:
            checks = []
            def injected_check(solver, *args):
                checks.append('unknown')
                return z3.unknown
            z3.Solver.check = injected_check
            z3.Solver.reason_unknown = lambda solver: reason
            try:
                x = Term('BVS', 32, ('x_' + str(len(rows)),))
                y = Term('BVS', 32, ('y_' + str(len(rows)),))
                relation = Term('Eq', None, (Term('Mul', 32, (x, y)), Term('BVV', 32, (7,))))
                result = adapter.solve(SolverQuery((relation,), origin='fault injection: ' + reason))
                rows.append({'reason': reason, 'expected': expected, 'check_calls': len(checks),
                             'result': result.to_dict(), 'passed': len(checks) > 0 and result.status.value == expected})
            finally:
                z3.Solver.check, z3.Solver.reason_unknown = original_check, original_reason
        report = {'kind': 'fault injection; not a naturally occurring unknown query', 'cases': rows,
                  'violations': guard.violations,
                  'gate': 'PASS' if all(r['passed'] for r in rows) and not guard.violations else 'FAIL'}
        with (folder / 'report.json').open('x', encoding='utf8') as f:
            json.dump(report, f, indent=2)
    finally:
        guard.restore()
    print(json.dumps(report))
    return 0 if report['gate'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
