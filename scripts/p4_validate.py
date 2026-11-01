"""P4 gate: guarded native probes, bounded firmware comparison and integrity."""
import argparse
import ast
import datetime as dt
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
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    evidence = parser.parse_args().evidence.resolve()
    evidence.relative_to(TARGET / '.p4-work')
    if not (evidence / 'legacy-before.json').is_file():
        raise RuntimeError('Phase-start checkpoint required')
    folder = evidence / ('validation-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                          + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(exist_ok=False)
    (folder / 'native').mkdir()
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env.pop('PYTHONPATH', None)
    env.pop('VIRTUAL_ENV', None)
    interpreter = str(TARGET / '.venv/Scripts/python.exe')
    commands = (
        ('pure-input-tests', [interpreter, '-B', '-S', '-m', 'unittest', 'discover', '-s', 'tests', '-p', 'test_p4_inputs.py', '-v']),
        ('all-tests', [interpreter, '-B', '-m', 'unittest', 'discover', '-s', 'tests', '-v']),
        ('native-frontends', [interpreter, '-B', str(TARGET / 'scripts/p4_probe.py'), '--folder', str(folder / 'native'), '--firmware']),
        ('diff-check', ['git', '--no-optional-locks', 'diff', '--check', '--', '.', ':!.venv']),
    )
    receipts = []
    for label, command in commands:
        started = time.monotonic()
        with (folder / (label + '.stdout.txt')).open('xb') as out, (folder / (label + '.stderr.txt')).open('xb') as err:
            process = subprocess.Popen(command, cwd=TARGET, env=env, stdout=out, stderr=err)
            timed_out = False
            try:
                process.wait(timeout=240)
            except subprocess.TimeoutExpired:
                sys.path.insert(0, str(TARGET))
                from emtaint.solver.process_port import terminate_tree
                terminate_tree(process)
                timed_out = True
        stderr = (folder / (label + '.stderr.txt')).read_text(encoding='utf8', errors='replace')
        match = re.search(r'Ran (\d+) tests', stderr)
        receipt = {'name': label, 'command': command, 'exit_code': process.returncode,
                   'tests': int(match.group(1)) if match else None, 'timed_out': timed_out,
                   'wall_seconds': time.monotonic() - started}
        receipts.append(receipt)
        print(json.dumps(receipt), flush=True)
    write(folder / 'commands.json', receipts)
    report_path = folder / 'native/native-report.json'
    native = json.loads(report_path.read_text(encoding='utf8')) if report_path.exists() else {'passed': False}
    roots = {'legacy': TARGET.parent / 'EmTaint', 'target-venv': TARGET / '.venv',
        'golden': TARGET.parent / 'baselines', 'p1-sealed': TARGET / '.p1-work/20261028T081314Z-a53352b3',
        'p2-sealed': TARGET / '.p2-work/20261028T083140Z-bcf22249',
        'p3-sealed': TARGET / '.p3-work/20261028T090527Z-dba03447',
        'old-frontend': TARGET / 'emtaint/frontend', 'p3-ir': TARGET / 'emtaint/ir'}
    integrity = {}
    for name, root in roots.items():
        records = full_inventory(root)
        write(folder / (name + '-after.json'), records)
        before = json.loads((evidence / (name + '-before.json')).read_text(encoding='utf8'))
        integrity[name] = {'unchanged': records == before, 'files': len(records)}
        print(json.dumps({name: integrity[name]}), flush=True)
    documents = {name: (TARGET / name).read_bytes() == (evidence / 'planning-source' / name).read_bytes()
                 for name in ('AGENTS.md', 'MIGRATION_BLUEPRINT.md', 'CODE_TASK.md')}
    # The frozen v1 contract is consumed, never modified to fit frontend output.
    source = TARGET / '.p3-work/20261028T090527Z-dba03447/final-source'
    contract_unchanged = all((TARGET / f.relative_to(source)).read_bytes() == f.read_bytes()
        for f in source.rglob('*') if f.is_file() and f.suffix in ('.py', '.json'))
    files = list((TARGET / 'emtaint/frontends').rglob('*.py')) + [
        TARGET / 'tests/test_p4_inputs.py', TARGET / 'tests/p4_native_cases.py',
        TARGET / 'scripts/p4_probe.py', Path(__file__).resolve()]
    for file in files:
        text = file.read_text(encoding='utf-8-sig')
        ast.parse(text, filename=str(file))
        if any(line != line.rstrip() for line in text.splitlines()):
            raise RuntimeError('Trailing whitespace in new source: ' + str(file))
    versions = {name: importlib.metadata.version(name) for name in ('angr', 'pyvex', 'cle', 'archinfo', 'claripy')}
    passed = (all(r['exit_code'] == 0 and not r['timed_out'] for r in receipts) and native.get('passed')
              and all(r['unchanged'] for r in integrity.values()) and all(documents.values()) and contract_unchanged)
    result = {'phase': 'P4', 'gate': 'PASS' if passed else 'FAIL',
        'scope': 'Two VEX input paths and bounded frontend comparison; unsupported effects explicit',
        'commands': receipts, 'native': native, 'integrity': integrity, 'planning_docs_unchanged': documents,
        'p3_contract_sources_and_schemas_unchanged': contract_unchanged,
        'python': sys.version, 'runtime_packages': versions,
        'old_firmware_analysis_cli': 'NOT_EXECUTED', 'ida_host_api': 'NOT_EXECUTED; existing export consumed read-only',
        'gate_m': 'NOT_IMPLEMENTED / P5 REQUIRED', 'gate_a': 'NOT_EXECUTED', 'rust': 'NOT_IMPLEMENTED'}
    write(folder / 'validation-p4.json', result)
    print('VALIDATION=' + str(folder / 'validation-p4.json'), flush=True)
    print('P4 GATE=' + result['gate'], flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
