"""P3 contract gate with immutable integrity evidence. No firmware/native probes."""
import argparse
import ast
import datetime as dt
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from baseline_inventory import full_inventory

TARGET = Path(__file__).resolve().parents[1]


def write(path, value):
    with path.open('x', encoding='utf8') as f:
        json.dump(value, f, indent=2)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('evidence', type=Path)
    evidence = p.parse_args().evidence.resolve()
    evidence.relative_to(TARGET / '.p3-work')
    if not (evidence / 'legacy-before.json').is_file():
        raise RuntimeError('Phase-start checkpoint required')
    folder = evidence / ('validation-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                         + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(exist_ok=False)
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env.pop('PYTHONPATH', None)
    env.pop('VIRTUAL_ENV', None)
    interpreter = str(TARGET / '.venv/Scripts/python.exe')
    commands = (
        ('pure-contract-tests', [interpreter, '-B', '-S', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_p3_contracts.py', '-v']),
        ('memory-conformance-contracts', [interpreter, '-B', '-S', '-m', 'unittest', 'discover', '-s', 'tests/conformance', '-t', 'tests', '-v']),
        ('all-tests', [interpreter, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v']),
        ('diff-check', ['git', '--no-optional-locks', 'diff', '--check', '--', '.', ':!.venv']),
    )
    receipts = []
    for label, command in commands:
        start = time.monotonic()
        result = subprocess.run(command, cwd=TARGET, env=env, capture_output=True, text=True)
        (folder / (label + '.stdout.txt')).write_text(result.stdout, encoding='utf8')
        (folder / (label + '.stderr.txt')).write_text(result.stderr, encoding='utf8')
        count = re.search(r'Ran (\d+) tests', result.stderr)
        receipt = {'name': label, 'command': command, 'exit_code': result.returncode,
                   'tests': int(count.group(1)) if count else None, 'wall_seconds': time.monotonic() - start}
        receipts.append(receipt)
        print(json.dumps(receipt), flush=True)
    write(folder / 'commands.json', receipts)
    sys.path.insert(0, str(TARGET))
    sys.path.insert(0, str(TARGET / 'tests'))
    from conformance.memory.fixtures import CASES, exercise, snapshot_fixture
    from test_p3_contracts import sample_module
    from emtaint.ir.canonical.wire import dumps, loads, schema_documents
    from dataclasses import replace
    cases = [exercise(case) for case in CASES]
    write(folder / 'M-01-M-12.json', cases)
    module = replace(sample_module(), memory_snapshots=(snapshot_fixture(),),
        capabilities=('typed-effects', 'memory-descriptors', 'access-graph-descriptors', 'taint-fact-descriptors'))
    text = dumps(module)
    assert loads(text) == module
    (folder / 'cir-memory-fixture.json').write_text(text, encoding='utf8')
    snapshot = snapshot_fixture()
    (folder / 'memory-fixture.json').write_text(dumps(snapshot), encoding='utf8')
    schemas_equal = all(json.loads((TARGET / 'docs/migration/schemas' / name).read_text(encoding='utf8')) == value
                        for name, value in schema_documents().items())
    integrity = {}
    roots = {'legacy': TARGET.parent / 'EmTaint', 'target-venv': TARGET / '.venv',
             'golden': TARGET.parent / 'baselines', 'p1-sealed': TARGET / '.p1-work/20261028T081314Z-a53352b3',
             'p2-sealed': TARGET / '.p2-work/20261028T083140Z-bcf22249', 'legacy-vex-ir': TARGET / 'emtaint/ir'}
    for name, root in roots.items():
        records = full_inventory(root)
        if name == 'legacy-vex-ir':
            records = [r for r in records if not r['path'].startswith('canonical/')]
        before = json.loads((evidence / (name + '-before.json')).read_text(encoding='utf8'))
        write(folder / (name + '-after.json'), records)
        integrity[name] = {'unchanged': before == records, 'files': len(records)}
        print(json.dumps({name: integrity[name]}), flush=True)
    documents = {name: {'unchanged': (TARGET / name).read_bytes() == (evidence / 'planning-source' / name).read_bytes(),
        'sha256': hashlib.sha256((TARGET / name).read_bytes()).hexdigest()}
        for name in ('AGENTS.md', 'MIGRATION_BLUEPRINT.md', 'CODE_TASK.md')}
    # New contract code never rewrites previously accepted P2 implementation.
    p2 = TARGET / '.p2-work/20261028T083140Z-bcf22249/final-source'
    p2_source_unchanged = all((TARGET / source.relative_to(p2)).read_bytes() == source.read_bytes()
                            for source in p2.rglob('*') if source.is_file() and source.name != '.gitignore')
    source_files = [TARGET / 'emtaint/core/contracts.py', TARGET / 'emtaint/solver/lowering.py',
                    TARGET / 'tests/test_p3_contracts.py', TARGET / 'tests/schema_shape.py', Path(__file__).resolve()]
    for relative in ('emtaint/ir/canonical', 'emtaint/memory', 'tests/conformance'):
        source_files.extend((TARGET / relative).rglob('*.py'))
    for file in source_files:
        source = file.read_text(encoding='utf-8-sig')
        ast.parse(source, filename=str(file))
        if any(line != line.rstrip() for line in source.splitlines()):
            raise RuntimeError('New source has trailing whitespace: ' + str(file))
    versions = {name: importlib.metadata.version(name) for name in
                ('angr', 'claripy', 'pyvex', 'cle', 'archinfo', 'z3-solver')}
    write(folder / 'runtime.json', {'python': sys.version, 'executable': sys.executable,
                                   'packages_metadata_only': versions})
    passed = (all(r['exit_code'] == 0 for r in receipts) and all(r['unchanged'] for r in integrity.values())
              and all(r['unchanged'] for r in documents.values()) and p2_source_unchanged and schemas_equal
              and all(c['contract_status'] == 'PASS' and c['runtime_gate_m'] == 'NOT_IMPLEMENTED' for c in cases))
    result = {'phase': 'P3', 'gate': 'PASS' if passed else 'FAIL', 'commands': receipts,
        'integrity': integrity, 'documents': documents, 'p2_source_unchanged': p2_source_unchanged,
        'schema_documents_match_runtime': schemas_equal, 'schema_types': len(next(iter(schema_documents().values()))['$defs']),
        'fixture_roundtrip_bytes': len(text.encode('utf8')), 'fixtures_contract_passed': len(cases),
        'gate_m': 'NOT_IMPLEMENTED / P5 REQUIRED', 'gate_a': 'NOT_EXECUTED',
        'native_frontend_or_firmware_analysis_executed': False, 'solver_calls_in_p3_fixtures': 0,
        'rust_development': False, 'new_python_sources_syntax_checked': len(source_files)}
    write(folder / 'validation-p3.json', result)
    print('VALIDATION=' + str(folder / 'validation-p3.json'), flush=True)
    print('P3 CONTRACT GATE=' + result['gate'], flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
