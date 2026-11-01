"""Guarded target-only native P4 tests and bounded real firmware frontend comparison."""
import argparse
import ctypes
import faulthandler
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
import unittest

TARGET = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TARGET))
sys.path.insert(0, str(TARGET / 'tests'))
from p1_runtime import ProbeWriteGuard


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder', type=Path, required=True)
    parser.add_argument('--firmware', action='store_true')
    args = parser.parse_args()
    folder = args.folder.resolve()
    folder.relative_to(TARGET / '.p4-work')
    if not folder.is_dir() or (folder / 'native-report.json').exists():
        raise RuntimeError('Fresh existing P4 folder required')
    cache = folder / 'cache'
    cache.mkdir(exist_ok=False)
    for key in ('TEMP', 'TMP', 'TMPDIR'):
        os.environ[key] = str(cache)
    tempfile.tempdir = str(cache)
    sys.dont_write_bytecode = True
    if sys.platform == 'win32':
        ctypes.windll.kernel32.SetErrorMode(3)
    faulthandler.enable()
    guard = ProbeWriteGuard([folder]).install()
    report = {'native_tests': None, 'firmware': None}
    try:
        import p4_native_cases as cases
        cases.WORK = folder
        with (folder / 'native-tests.txt').open('x', encoding='utf8') as out:
            result = unittest.TextTestRunner(stream=out, verbosity=2).run(unittest.defaultTestLoader.loadTestsFromModule(cases))
        report['native_tests'] = {'run': result.testsRun, 'failures': len(result.failures), 'errors': len(result.errors), 'passed': result.wasSuccessful()}
        if args.firmware:
            from emtaint.frontends.inputs import read_ida_cfg, ELFImage
            from emtaint.frontends.angr_vex import AngrVexFrontend
            from emtaint.frontends.ida_vex import IdaVexFrontend
            from emtaint.ir.canonical.wire import dumps, loads
            binary = TARGET.parent / 'EmTaint/firmware-binaries/rv130_v44/httpd'
            metadata = TARGET.parent / 'EmTaint/data/ida_data/rv130_1_0_3_44/httpd_cfg.json'
            all_specs = read_ida_cfg(metadata)
            # Real multi-block functions selected by deterministic bounded input
            # size, including a function containing explicit zero-byte boundaries.
            normal = sorted((s for s in all_specs if 2 <= len(s.blocks) <= 8 and not any(b.boundary for b in s.blocks)),
                            key=lambda s: (sum(b.end-b.start for b in s.blocks), s.address))[:3]
            boundaries = sorted((s for s in all_specs if any(b.boundary for b in s.blocks)),
                                key=lambda s: (sum(b.end-b.start for b in s.blocks), s.address))[:1]
            specs = tuple(sorted(normal + boundaries, key=lambda s: s.address))
            a = AngrVexFrontend(binary).lift(specs)
            b = IdaVexFrontend(binary).from_metadata(metadata, function_addresses=tuple(s.address for s in specs))
            same = cases.normalized(a.module) == cases.normalized(b.module)
            comparisons = {'semantic_module_equal_except_producer': same, 'block_mapping_equal': a.mappings == b.mappings,
                           'cfg_equal': a.cfgs() == b.cfgs()}
            for label, value in (('angr', a), ('ida', b)):
                text = dumps(value.module)
                assert loads(text) == value.module
                (folder / (label + '-firmware-cir.json')).write_text(text, encoding='utf8')
                with (folder / (label + '-firmware-report.json')).open('x', encoding='utf8') as out:
                    json.dump(value.report(), out, indent=2)
            report['firmware'] = {'selection': [hex(s.address) for s in specs],
                'input_functions_total': len(all_specs), 'functions_with_boundary_nodes': sum(any(b.boundary for b in s.blocks) for s in all_specs),
                'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
                'metadata_sha256': hashlib.sha256(metadata.read_bytes()).hexdigest(), **comparisons,
                'angr': {k:v for k,v in a.report().items() if k not in ('coverage', 'block_mappings', 'metadata')},
                'irsbs': sum(not m['lift_failure'] for m in a.mappings),
                'input_boundaries': sum(m['lift_failure'].startswith('InputBoundary:') for m in a.mappings),
                'expression_histogram': a.metadata['expression_histogram'],
                'native_control_edges': len(a.metadata['native_control_flow']),
                'cfg_edges': sum(len(g.edges) for g in a.cfgs()),
                'cfg_unknown_edges': sum(e.kind.value == 'unknown' for g in a.cfgs() for e in g.edges),
                'source_blocks': sum(len(s.blocks) for s in specs)}
        report['passed'] = report['native_tests']['passed'] and (not args.firmware or all(comparisons.values()))
    except BaseException as error:
        traceback.print_exc()
        report.update(passed=False, error=type(error).__name__ + ': ' + str(error))
    finally:
        report['violations'] = guard.violations
        if guard.violations:
            report['passed'] = False
        with (folder / 'native-report.json').open('x', encoding='utf8') as out:
            json.dump(report, out, indent=2)
        guard.restore()
    print(json.dumps(report), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
