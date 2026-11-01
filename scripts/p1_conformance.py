"""Real target SolverPort conformance; fresh evidence only, no firmware runs."""
import argparse
import json
from pathlib import Path
import sys

TARGET = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TARGET))
from emtaint.solver.port import SolverQuery, SolverStatus, Term
from emtaint.solver.process_port import SubprocessSolverPort


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    root = parser.parse_args().evidence.resolve()
    root.relative_to(TARGET / '.p1-work')
    folder = root / 'native-conformance'
    folder.mkdir(exist_ok=False)
    port = SubprocessSolverPort(folder / 'requests')
    x = Term('BVS', 8, ('x',))
    bv = lambda n: Term('BVV', 8, (n,))
    eq = lambda a, b: Term('Eq', None, (a, b))
    true = Term('BoolV', None, (True,))
    rows = []

    def check(name, query, status, values=None):
        result = port.solve(query)
        passed = result.status == status and (values is None or set(result.values) == set(values))
        rows.append({'name': name, 'passed': passed, 'expected_status': status.value,
                     'expected_values': values, 'result': result.to_dict()})
        print(json.dumps(rows[-1]), flush=True)

    check('sat', SolverQuery((eq(x, bv(7)),)), SolverStatus.SAT)
    check('unsat', SolverQuery((eq(x, bv(7)), eq(x, bv(8)))), SolverStatus.UNSAT)
    check('eval', SolverQuery((eq(x, bv(7)),), x, 'eval', limit=2), SolverStatus.SAT, [7])
    bounds = (Term('ULE', None, (bv(3), x)), Term('ULE', None, (x, bv(5))))
    check('eval-enumeration', SolverQuery(bounds, x, 'eval', limit=4), SolverStatus.SAT, [3, 4, 5])
    check('min', SolverQuery(bounds, x, 'min'), SolverStatus.SAT, [3])
    check('max', SolverQuery(bounds, x, 'max'), SolverStatus.SAT, [5])
    check('unsigned-255', SolverQuery((eq(x, bv(255)), Term('ULT', None, (x, bv(1))))), SolverStatus.UNSAT)
    check('signed-negative', SolverQuery((eq(x, bv(255)), Term('SLT', None, (x, bv(1))))), SolverStatus.SAT)
    terms = {
        'wrap': (Term('Add', 8, (bv(255), bv(2))), [1]),
        'extract': (Term('Extract', 4, (7, 4, bv(0xab))), [10]),
        'concat': (Term('Concat', 16, (bv(0x12), bv(0x34))), [0x1234]),
        'zero-ext': (Term('ZeroExt', 16, (8, bv(0x80))), [128]),
        'sign-ext': (Term('SignExt', 16, (8, bv(0x80))), [0xff80]),
        'conditional': (Term('If', 8, (true, bv(7), bv(9))), [7]),
    }
    for name, (expression, values) in terms.items():
        check(name, SolverQuery((true,), expression, 'eval'), SolverStatus.SAT, values)
    check('memory-unsupported', SolverQuery((eq(Term('Load', 8, (x,)), bv(7)),)), SolverStatus.UNSUPPORTED)
    # Real bounded SMT timeout. Keep the actual result; accept neither UNKNOWN
    # nor UNSAT as a substitute for the timeout fixture's expected TIMEOUT.
    pigeons = [Term('BVS', 5, ('pigeon_' + str(i),)) for i in range(32)]
    constraints = [Term('ULT', None, (t, Term('BVV', 5, (31,)))) for t in pigeons]
    constraints += [Term('Not', None, (eq(pigeons[i], pigeons[j]),)) for i in range(32) for j in range(i)]
    check('real-1ms-timeout', SolverQuery(tuple(constraints), timeout_ms=1), SolverStatus.TIMEOUT)
    report = {'gate': 'PASS' if all(r['passed'] for r in rows) else 'FAIL', 'cases': rows}
    with (folder / 'report.json').open('x', encoding='utf8') as stream:
        json.dump(report, stream, indent=2)
    return 0 if report['gate'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())
