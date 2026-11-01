"""Validate P2 models and preserve evidence; no firmware or native frontend runs."""
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


def visitor_differential(before):
    """Prove only the allocator owner changed in all old visitor dispatch logic."""
    tree = ast.parse(before.read_text(encoding='utf-8-sig'))
    class Normalize(ast.NodeTransformer):
        count = 0
        def visit_ImportFrom(self, node):
            if node.module == 'var_node' and node.level == 1:
                return None
            return node
        def visit_Call(self, node):
            self.generic_visit(node)
            if isinstance(node.func, ast.Name) and node.func.id == 'VarNode':
                self.count += 1
                node.func = ast.parse('self.ir_graph.new_node', mode='eval').body
            return node
    transformer = Normalize()
    expected = transformer.visit(tree)
    actual = ast.parse((TARGET / 'emtaint/analysis/pag/visitor.py').read_text(encoding='utf-8-sig'))
    return {'allocations_routed': transformer.count,
            'remaining_dispatch_ast_equal': ast.dump(expected) == ast.dump(actual)}


def model_smoke():
    sys.path.insert(0, str(TARGET))
    sys.path.insert(0, str(TARGET / 'tests'))
    from test_program_models import fixture
    from emtaint.core import AnalysisSession, ContextId, MemoryObjectId, MemoryObject
    from emtaint.graph import FlowEdge, CallEdge, TargetKind
    started = time.perf_counter()
    p, fid, callee, a, b, _, site = fixture()
    session = AnalysisSession(p)
    session.replace_cfg(session.cfg(fid).with_edge(FlowEdge(a, b)))
    session.replace_cg(session.cg.with_edge(CallEdge(site, callee, TargetKind.MAY, 'fixture candidate')))
    context = ContextId((site,))
    identities = (MemoryObjectId.stack(fid, context, 'frame-1', -8),
                  MemoryObjectId.global_object(p.binary, '.data', 0),
                  MemoryObjectId.heap(site.point, context), MemoryObjectId.argument(fid, 0, context),
                  MemoryObjectId.return_value(fid, context),
                  MemoryObjectId.unknown(p.binary, 'any', 'unresolved', site.token, context))
    for identity in identities:
        session.register_object(MemoryObject(identity, 'P2 identity fixture'))
    session.cache_put('fixture', 'value', (fid.token, context.token))
    session.summary_put(fid, context, ('unresolved',))
    before = session.stamp
    session.replace_cfg(session.cfg(fid).without_edge(FlowEdge(a, b)))
    invalidated = (session.stamp != before and session.cache_get('fixture', 'value') is None
                   and session.summary_get(fid, context) is None)
    return {'kind': 'synthetic P2 model fixture; not a firmware analysis',
            'functions': len(p.functions), 'blocks': sum(len(f.blocks) for f in p.functions),
            'cfg_edges_after_removal': sum(len(g.edges) for g in session.cfgs.values()),
            'cg_edges': len(session.cg.edges), 'unresolved_callsites': len(session.cg.unresolved_sites),
            'contexts': len(session.contexts), 'memory_identity_descriptors': len(session.objects),
            'cfg_change_invalidated_cache_and_summary': invalidated,
            'status': session.status.value, 'apg_nodes': None, 'apg_edges': None,
            'abstract_heap_objects': None, 'heap_cells': None, 'memory_versions': None,
            'sse_dag_nodes': None, 'propagation_facts': None, 'worklist_iterations': None,
            'solver_calls': 0, 'wall_seconds': time.perf_counter() - started,
            'peak_rss': None}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('evidence', type=Path)
    evidence = parser.parse_args().evidence.resolve()
    evidence.relative_to(TARGET / '.p2-work')
    if not (evidence / 'legacy-before.json').is_file():
        raise RuntimeError('Require the existing phase-start integrity checkpoint')
    folder = evidence / ('validation-' + dt.datetime.now(dt.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
                         + '-' + uuid.uuid4().hex[:8])
    folder.mkdir(exist_ok=False)
    env = os.environ.copy()
    env['PYTHONDONTWRITEBYTECODE'] = '1'
    env.pop('PYTHONPATH', None)
    env.pop('VIRTUAL_ENV', None)
    commands = [
        ('pure-model-tests', [str(TARGET / '.venv/Scripts/python.exe'), '-B', '-S', '-m', 'unittest',
                              'discover', '-s', 'tests', '-p', 'test_program*.py', '-v']),
        ('all-tests', [str(TARGET / '.venv/Scripts/python.exe'), '-B', '-m', 'unittest',
                       'discover', '-s', 'tests', '-v']),
        ('diff-check', ['git', '--no-optional-locks', 'diff', '--check', '--', '.', ':!.venv']),
    ]
    receipts = []
    for label, command in commands:
        start = time.monotonic()
        result = subprocess.run(command, cwd=TARGET, env=env, capture_output=True, text=True)
        (folder / (label + '.stdout.txt')).write_text(result.stdout, encoding='utf8')
        (folder / (label + '.stderr.txt')).write_text(result.stderr, encoding='utf8')
        count = re.search(r'Ran (\d+) tests', result.stderr)
        receipt = {'name': label, 'command': command, 'exit_code': result.returncode,
                   'tests': int(count.group(1)) if count else None,
                   'wall_seconds': time.monotonic() - start}
        receipts.append(receipt)
        print(json.dumps(receipt), flush=True)
    write(folder / 'commands.json', receipts)
    differential = visitor_differential(evidence / 'before-source/emtaint/analysis/pag/visitor.py')
    write(folder / 'visitor-differential.json', differential)
    smoke = model_smoke()
    write(folder / 'model-smoke.json', smoke)
    versions = {name: importlib.metadata.version(name) for name in
                ('angr', 'claripy', 'cle', 'pyvex', 'archinfo', 'z3-solver')}
    write(folder / 'runtime.json', {'executable': sys.executable, 'python': sys.version,
                                    'packages_metadata_only': versions})
    roots = {'legacy': TARGET.parent / 'EmTaint', 'target-venv': TARGET / '.venv',
             'golden': TARGET.parent / 'baselines',
             'p1-sealed': TARGET / '.p1-work/20261028T081314Z-a53352b3'}
    integrity = {}
    for name, root in roots.items():
        after = full_inventory(root)
        before = json.loads((evidence / (name + '-before.json')).read_text(encoding='utf8'))
        write(folder / (name + '-after.json'), after)
        integrity[name] = {'unchanged': before == after, 'files': len(after)}
        print(json.dumps({name: integrity[name]}), flush=True)
    documents = {}
    for name in ('AGENTS.md', 'MIGRATION_BLUEPRINT.md', 'CODE_TASK.md'):
        before = (evidence / 'before-source' / name).read_bytes()
        after = (TARGET / name).read_bytes()
        documents[name] = {'unchanged': before == after, 'sha256': hashlib.sha256(after).hexdigest()}
    passed = (all(r['exit_code'] == 0 for r in receipts) and all(r['unchanged'] for r in integrity.values())
              and all(r['unchanged'] for r in documents.values()) and differential['allocations_routed'] == 28
              and differential['remaining_dispatch_ast_equal'] and smoke['cfg_change_invalidated_cache_and_summary'])
    result = {'phase': 'P2', 'gate': 'PASS' if passed else 'FAIL', 'commands': receipts,
              'integrity': integrity, 'documents': documents, 'visitor_differential': differential,
              'model_smoke': smoke, 'native_frontend_or_firmware_analysis_executed': False,
              'memory_semantics_gate_m': 'NOT_EXECUTED', 'end_to_end_gate_a': 'NOT_EXECUTED'}
    write(folder / 'validation-p2.json', result)
    print('VALIDATION=' + str(folder / 'validation-p2.json'), flush=True)
    print('P2 GATE=' + result['gate'], flush=True)
    return 0 if passed else 1


if __name__ == '__main__':
    raise SystemExit(main())
