"""Read-only native old register-substitution probe for P7.2."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
import types

from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation

TARGET = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--folder', type=Path, required=True)
    args = parser.parse_args()
    folder = args.folder.resolve()
    folder.relative_to(TARGET / '.p7-work')
    folder.mkdir(exist_ok=False)
    cache = folder / 'cache'
    cache.mkdir()
    for name in ('TEMP', 'TMP', 'TMPDIR'):
        os.environ[name] = str(cache)
    tempfile.tempdir = str(cache)
    sys.dont_write_bytecode = True
    guard = ProbeWriteGuard([folder]).install()
    report = {
        'scope': 'Actual old AccurateDataFlow._update_register_in_expr with controlled TraceExpr; no CLI or target proof',
        'interpreter': sys.executable,
        'script_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
    }
    try:
        report['ply'] = install_ply_isolation(cache, 'disabled')
        package = types.ModuleType('dataflow')
        package.__path__ = [str(TARGET.parent / 'EmTaint' / 'dataflow')]
        sys.modules['dataflow'] = package
        import claripy
        from dataflow.accurate_data_flow import AccurateDataFlow
        from dataflow.variable_expression import construct_trace_expr
        from dataflow.code_location import CodeLocation
        from dataflow.global_config import section_regions, basic_types, arch_info

        arch_info['bits'] = 32
        basic_types['default'] = basic_types[32]
        section_regions['.loader'] = (0x1000, 0x2000)

        engine = AccurateDataFlow.__new__(AccurateDataFlow)
        old_file = TARGET.parent / 'EmTaint' / 'dataflow' / 'accurate_data_flow.py'
        report['old_source_sha256'] = hashlib.sha256(old_file.read_bytes()).hexdigest()
        rows = []
        r4 = claripy.BVS('r4', 32, explicit_name=True)
        for label, ast, replacement, expected in (
            ('register_copy', r4, 'r8', 'r8'),
            ('arithmetic_offset', r4 + claripy.BVV(3, 32), 'r8', 'r8'),
            ('clean_constant', r4, 0, None),
        ):
            trace = construct_trace_expr(ast, pattern='LBF', data_type='Tdata',
                trace_dir='B', block_addr=0x1000, stmt_idx=0, index=0,
                var_type='ptr', base_ptr='r4')
            result = engine._update_register_in_expr('r4', replacement, 'ptr',
                                                     0, 1, trace)
            variables = sorted(result.expr.ast.variables)
            passed = 'r4' not in variables and (expected is None or expected in variables)
            if expected is None:
                passed = passed and not variables
            rows.append({'case': label, 'input': str(ast), 'replacement': replacement,
                'output': str(result.expr.ast), 'variables': variables,
                'trace_dir': result.expr.trace_dir, 'passed': passed})
        for label, replacement, expected in (
            ('temporary_register', 'r8', 'r8'),
            ('temporary_constant', 0, None),
        ):
            trace = construct_trace_expr(claripy.BVS('t4', 32, explicit_name=True),
                pattern='LBF', data_type='Tdata', trace_dir='B', block_addr=0x1000,
                stmt_idx=0, index=0, var_type='ptr', base_ptr='t4')
            result = engine._find_wrtmp_def_v1('t4', replacement, 32,
                CodeLocation(0x1000, 1), 'ptr', trace)[0]
            variables = sorted(result.expr.ast.variables)
            passed = 't4' not in variables and (expected in variables if expected else not variables)
            rows.append({'case': label, 'input': '<BV32 t4>',
                'replacement': replacement, 'output': str(result.expr.ast),
                'variables': variables, 'location': str(result.expr.location),
                'passed': passed})
        report['cases'] = rows
        report['passed'] = all(row['passed'] for row in rows)
    except BaseException as error:
        traceback.print_exc()
        report.update(passed=False, error=type(error).__name__ + ': ' + str(error))
    finally:
        report['violations'] = guard.violations
        report['passed'] = report.get('passed', False) and not guard.violations
        with (folder / 'legacy-intra-report.json').open('x', encoding='utf8') as stream:
            json.dump(report, stream, indent=2)
        guard.restore()
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
