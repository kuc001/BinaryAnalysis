"""P2 model contracts. All fixtures work with Python -S and no native libraries."""
from dataclasses import FrozenInstanceError, replace
from pathlib import Path
import json
import os
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from emtaint.core import (ABI, Architecture, Register, Endian, BinaryId, FunctionId,
    BlockId, ProgramPoint, CallSiteId, ContextId, MemoryObjectId, MemoryKind,
    BasicBlock, Function, CallSite, CallKind, Program, Completeness, MemoryObject,
    AnalysisSession, BudgetLimits, BudgetExceeded)
from emtaint.graph import (ControlFlowGraph, FlowEdge, FlowKind, CallGraph,
                           CallEdge, TargetKind)


def fixture(content=b'fixture', image_base=0x1000):
    binary = BinaryId.from_bytes(content)
    fid, callee = FunctionId(binary, 0), FunctionId(binary, 16)
    a, b, c = BlockId(fid, 0), BlockId(fid, 4), BlockId(callee, 16)
    site = CallSiteId(ProgramPoint(a, 0, 1))
    arch = Architecture('fixture32', 32, 32, Endian.LITTLE,
                        registers=(Register('sp', 32), Register('a0', 32), Register('v0', 32)))
    abi = ABI('fixture-abi', ('a0',), ('v0',), stack_pointer='sp', stack_alignment=4)
    program = Program(binary, arch, abi,
        (Function(fid, 'entry', (BasicBlock(a, 4), BasicBlock(b, 4)), a),
         Function(callee, 'callee', (BasicBlock(c, 4),), c)),
        (CallSite(site, CallKind.INDIRECT),), image_base=image_base)
    return program, fid, callee, a, b, c, site


class IdentityTests(unittest.TestCase):
    def test_binary_and_function_scope(self):
        p, fid, *_ = fixture()
        q, other, *_ = fixture(b'another image')
        self.assertNotEqual(fid, other)
        self.assertNotEqual(fid.token, other.token)
        self.assertEqual(p.binary, BinaryId.from_bytes(b'fixture'))
        self.assertNotEqual(p.binary, q.binary)

    def test_rebase_keeps_ids_and_changes_addresses(self):
        p, fid, *_ = fixture()
        q, other, *_ = fixture(image_base=0x2000)
        self.assertEqual(fid, other)
        self.assertEqual(p.absolute_address(0), 0x1000)
        self.assertEqual(q.absolute_address(0), 0x2000)
        self.assertEqual(q.function_at(0x2000).id, fid)
        self.assertEqual(p.relative_address(0x1000), 0)

    def test_block_variants_and_program_points_are_distinct(self):
        _, fid, _, a, *_ = fixture()
        self.assertNotEqual(a, BlockId(fid, 0, index=1))
        self.assertNotEqual(a, BlockId(fid, 0, mode='thumb'))
        self.assertNotEqual(ProgramPoint(a, None), ProgramPoint(a, 0))
        self.assertNotEqual(ProgramPoint(a, 0, 0), ProgramPoint(a, 0, 1))
        self.assertNotEqual(CallSiteId(ProgramPoint(a, 0), 0), CallSiteId(ProgramPoint(a, 0), 1))

    def test_stable_tokens_across_hash_seeds_without_site_packages(self):
        code = ('from emtaint.core import *; b=BinaryId.from_bytes(b"fixture");'
                'p=ProgramPoint(BlockId(FunctionId(b,0),0),0,0);'
                'print(MemoryObjectId.heap(p,ContextId()).token)')
        values = []
        for seed in ('3', '97'):
            env = os.environ.copy()
            env['PYTHONHASHSEED'] = seed
            env.pop('PYTHONPATH', None)
            output = subprocess.run([sys.executable, '-B', '-S', '-c', code], cwd=ROOT,
                env=env, capture_output=True, text=True, check=True)
            values.append(output.stdout.strip())
        self.assertEqual(values[0], values[1])

    def test_invalid_and_mutable_identity_fields_rejected(self):
        _, fid, _, a, *_ = fixture()
        for build in (lambda: BinaryId('not-a-sha'), lambda: FunctionId(fid.binary, True),
                      lambda: BlockId(fid, -1), lambda: ProgramPoint(a, -1),
                      lambda: ContextId([]), lambda: Register('r0', True)):
            with self.subTest(build=build), self.assertRaises((TypeError, ValueError)):
                build()


class ProgramTests(unittest.TestCase):
    def test_zero_addresses_and_lookup(self):
        p, fid, _, a, _, _, site = fixture(image_base=0)
        self.assertEqual(p.function(fid).name, 'entry')
        self.assertEqual(p.function_at(0).id, fid)
        self.assertEqual(p.block(a).size, 4)
        self.assertEqual(p.callsite(site).kind, CallKind.INDIRECT)
        p.validate_point(site.point)

    def test_frozen_model_and_collections(self):
        p, fid, *_ = fixture()
        with self.assertRaises(FrozenInstanceError):
            p.image_base = 5
        with self.assertRaises(TypeError):
            replace(p, functions=list(p.functions))
        with self.assertRaises(FrozenInstanceError):
            p.function(fid).name = 'changed'

    def test_duplicate_and_foreign_references_fail(self):
        p, fid, _, a, _, _, site = fixture()
        for build in (lambda: replace(p, functions=p.functions + (p.function(fid),)),
                      lambda: replace(p, callsites=p.callsites * 2),
                      lambda: replace(p, binary=BinaryId.from_bytes(b'foreign')),
                      lambda: replace(p.function(fid), blocks=(BasicBlock(BlockId(fid, 99), 4),), entry=a),
                      lambda: replace(p, callsites=(CallSite(CallSiteId(ProgramPoint(a, 1, 4))),))):
            with self.subTest(build=build), self.assertRaises(ValueError):
                build()

    def test_architecture_abi_and_address_bounds(self):
        p, *_ = fixture()
        for build in (lambda: replace(p, abi=replace(p.abi, stack_pointer='missing')),
                      lambda: replace(p.architecture, registers=p.architecture.registers * 2),
                      lambda: replace(p, image_base=(1 << 32) - 1),
                      lambda: replace(p.abi, stack_alignment=3)):
            with self.subTest(build=build), self.assertRaises(ValueError):
                build()


class GraphTests(unittest.TestCase):
    def test_cfg_parallel_kinds_and_loop(self):
        _, fid, _, a, b, *_ = fixture()
        graph = ControlFlowGraph(fid, frozenset((a, b)), entry=a)
        edges = (FlowEdge(a, b, FlowKind.TRUE), FlowEdge(a, b, FlowKind.FALSE),
                 FlowEdge(b, a, FlowKind.JUMP))
        for edge in edges:
            graph = graph.with_edge(edge)
        self.assertEqual(len(graph.edges), 3)
        self.assertEqual(graph.successors(a), frozenset((b,)))
        self.assertEqual(graph.predecessors(a), frozenset((b,)))
        self.assertEqual(graph.with_edge(edges[0]), graph)
        self.assertEqual(len(graph.without_edge(edges[0]).edges), 2)

    def test_cfg_scope_and_dangling_edge_rejected(self):
        _, fid, _, a, b, c, _ = fixture()
        for build in (lambda: ControlFlowGraph(fid, frozenset((a, c))),
                      lambda: ControlFlowGraph(fid, frozenset((a,)), frozenset((FlowEdge(a, b),))),
                      lambda: ControlFlowGraph(fid, frozenset((a,)), entry=b)):
            with self.subTest(build=build), self.assertRaises(ValueError):
                build()

    def test_call_targets_retain_uncertainty_and_recursion(self):
        _, fid, callee, _, _, _, site = fixture()
        graph = CallGraph(frozenset((fid, callee)))
        graph = graph.with_edge(CallEdge(site, callee, TargetKind.MAY, 'candidate'))
        graph = graph.with_edge(CallEdge(site, fid, TargetKind.CONFIRMED, 'recursive call'))
        graph = graph.with_edge(CallEdge(site, None, TargetKind.UNKNOWN, 'remaining targets unresolved'))
        self.assertEqual(graph.targets(site), frozenset((fid, callee)))
        self.assertEqual(graph.targets(site, confirmed_only=True), frozenset((fid,)))
        self.assertIn(site, graph.unresolved_sites)
        with self.assertRaises(ValueError):
            CallEdge(site, None, TargetKind.CONFIRMED)

    def test_incomplete_graphs_cannot_be_labeled_complete(self):
        _, fid, callee, a, b, _, site = fixture()
        for build in (lambda: ControlFlowGraph(fid, frozenset((a, b)), status=Completeness.COMPLETE),
                      lambda: ControlFlowGraph(fid, frozenset((a, b)),
                          frozenset((FlowEdge(a, b, FlowKind.UNKNOWN),)), a, status=Completeness.COMPLETE),
                      lambda: CallGraph(frozenset((fid, callee)),
                          frozenset((CallEdge(site, None, reason='unresolved'),)), Completeness.COMPLETE)):
            with self.subTest(build=build), self.assertRaises(ValueError):
                build()


class MemoryIdentityTests(unittest.TestCase):
    def test_regions_and_register_overwrite_do_not_change_object_identity(self):
        p, fid, _, _, _, _, site = fixture()
        context = ContextId((site,))
        roots = (MemoryObjectId.stack(fid, context, 'frame-1', -8),
                 MemoryObjectId.global_object(p.binary, '.data', 0),
                 MemoryObjectId.heap(site.point, context),
                 MemoryObjectId.argument(fid, 0, context),
                 MemoryObjectId.return_value(fid, context),
                 MemoryObjectId.unknown(p.binary, 'any', 'unresolved', 'source-1', context))
        self.assertEqual({r.kind for r in roots}, set(MemoryKind))
        self.assertEqual(len({r.token for r in roots}), 6)
        registers = {'a0': roots[3]}
        registers['a0'] = roots[2]
        self.assertEqual(roots[3], MemoryObjectId.argument(fid, 0, context))
        self.assertNotEqual(roots[2], roots[3])

    def test_context_frame_and_allocation_instance_separate_ids(self):
        _, fid, _, _, _, _, site = fixture()
        root, nested = ContextId(), ContextId((site, site))
        self.assertNotEqual(MemoryObjectId.stack(fid, root, 'f'), MemoryObjectId.stack(fid, nested, 'f'))
        self.assertNotEqual(MemoryObjectId.stack(fid, root, 'f'), MemoryObjectId.stack(fid, root, 'g'))
        self.assertNotEqual(MemoryObjectId.heap(site.point, root, 'site-summary'),
                            MemoryObjectId.heap(site.point, root, 'instance-1'))
        with self.assertRaises(ValueError):
            MemoryObjectId.unknown(fid.binary, 'any', '', 'source')


class SessionTests(unittest.TestCase):
    def test_two_sessions_have_no_shared_state_or_revision_stamp(self):
        p, fid, *_ = fixture()
        a, b = AnalysisSession(p), AnalysisSession(p)
        a.cache_put('analysis', 'key', ('value', 1))
        a.summary_put(fid, ContextId(), ('summary',))
        self.assertIsNone(b.cache_get('analysis', 'key'))
        self.assertIsNone(b.summary_get(fid, ContextId()))
        self.assertNotEqual(a.stamp, b.stamp)
        self.assertEqual(len(a.cg.unresolved_sites), 1)

    def test_cfg_change_invalidates_cache_and_summary_idempotently(self):
        p, fid, _, a, b, *_ = fixture()
        session = AnalysisSession(p)
        old = session.cfg(fid)
        session.cache_put('flow', 'key', (1,))
        session.summary_put(fid, ContextId(), (2,))
        updated = old.with_edge(FlowEdge(a, b))
        session.replace_cfg(updated)
        self.assertEqual(session.cfg_version(fid), 1)
        self.assertIsNone(session.cache_get('flow', 'key'))
        self.assertIsNone(session.summary_get(fid, ContextId()))
        stamp = session.stamp
        session.replace_cfg(updated)
        self.assertEqual(session.stamp, stamp)
        self.assertEqual(len(old.edges), 0)

    def test_cg_change_invalidates_for_target_or_certainty_change(self):
        p, fid, callee, _, _, _, site = fixture()
        session = AnalysisSession(p)
        resolved = CallGraph(frozenset((fid, callee)), frozenset((CallEdge(site, callee, TargetKind.MAY, 'candidate'),)))
        session.cache_put('alias', 'key', None)
        session.replace_cg(resolved)
        self.assertIsNone(session.cache_get('alias', 'key'))
        self.assertEqual(session.cg_version, 1)
        stamp = session.stamp
        session.cache_put('alias', 'key', ('cached may target',))
        confirmed = replace(resolved, edges=frozenset((CallEdge(site, callee, TargetKind.CONFIRMED),)))
        session.replace_cg(confirmed)
        self.assertNotEqual(session.stamp, stamp)
        self.assertIsNone(session.cache_get('alias', 'key'))
        with self.assertRaises(ValueError):
            session.replace_cg(CallGraph(resolved.nodes))
        self.assertEqual(session.cg_version, 2)

    def test_budget_failure_is_explicit_atomic_and_incomplete(self):
        p, fid, _, a, b, *_ = fixture()
        session = AnalysisSession(p, BudgetLimits(max_graph_edges=1))
        before = session.stamp
        # Default unresolved CG edge consumes one edge already.
        with self.assertRaises(BudgetExceeded):
            session.replace_cfg(session.cfg(fid).with_edge(FlowEdge(a, b)))
        self.assertEqual(session.stamp, before)
        self.assertEqual(len(session.cfg(fid).edges), 0)
        self.assertEqual(session.status, Completeness.INCOMPLETE)
        self.assertEqual(session.diagnostics[-1].code, 'BUDGET_EXCEEDED')

    def test_context_object_and_cache_limits(self):
        p, fid, _, _, _, _, site = fixture()
        session = AnalysisSession(p, BudgetLimits(max_context_depth=1, max_cache_entries=1, max_objects=1))
        with self.assertRaises(BudgetExceeded):
            session.register_context(ContextId((site, site)))
        obj = MemoryObject(MemoryObjectId.argument(fid, 0, ContextId()), 'argument fixture')
        session.register_object(obj)
        session.register_object(obj)
        with self.assertRaises(BudgetExceeded):
            session.register_object(MemoryObject(MemoryObjectId.argument(fid, 1, ContextId()), 'second'))
        session.cache_put('test', 'one', None)
        with self.assertRaises(BudgetExceeded):
            session.cache_put('test', 'two', None)
        self.assertEqual(session.cache_get('test', 'one').value, None)

    def test_foreign_objects_points_and_mutable_payloads_are_rejected(self):
        p, fid, *_ = fixture()
        q, other, *_ = fixture(b'foreign')
        session = AnalysisSession(p)
        with self.assertRaises(ValueError):
            session.register_object(MemoryObject(MemoryObjectId.argument(other, 0, ContextId()), 'foreign'))
        for value in ([], {}, object(), ('nested', [])):
            with self.subTest(value=value), self.assertRaises(TypeError):
                session.cache_put('native', 'key', value)
        with self.assertRaises(TypeError):
            session.objects['bad'] = None

    def test_context_summary_limits_and_object_changes_invalidate(self):
        p, fid, _, _, _, _, site = fixture()
        session = AnalysisSession(p, BudgetLimits(max_contexts=1, max_summary_entries=1))
        with self.assertRaises(BudgetExceeded):
            session.register_context(ContextId((site,)))
        self.assertEqual(session.contexts, frozenset((ContextId(),)))
        session.summary_put(fid, ContextId(), (1,))
        other = p.functions[1].id
        with self.assertRaises(BudgetExceeded):
            session.summary_put(other, ContextId(), (2,))
        self.assertIsNone(session.summary_get(other, ContextId()))
        session.cache_put('alias', 'before-object', (3,))
        session.register_object(MemoryObject(MemoryObjectId.argument(fid, 0, ContextId()), 'fixture'))
        self.assertIsNone(session.summary_get(fid, ContextId()))
        self.assertIsNone(session.cache_get('alias', 'before-object'))

    def test_complete_status_requires_explicit_program_and_graph_coverage(self):
        p, fid, callee, _, _, _, site = fixture()
        p = replace(p, status=Completeness.COMPLETE, diagnostics=())
        session = AnalysisSession(p)
        self.assertEqual(session.status, Completeness.UNKNOWN)
        for cfg in tuple(session.cfgs.values()):
            session.replace_cfg(replace(cfg, status=Completeness.COMPLETE, reason='fixture graph coverage'))
        session.replace_cg(CallGraph(frozenset((fid, callee)),
            frozenset((CallEdge(site, callee, TargetKind.CONFIRMED),)),
            status=Completeness.COMPLETE, reason='fixture target coverage'))
        self.assertEqual(session.status, Completeness.COMPLETE)

    def test_payload_budget_does_not_silently_drop_an_analysis_result(self):
        p, *_ = fixture()
        session = AnalysisSession(p)
        with self.assertRaises(BudgetExceeded):
            session.cache_put('metadata', 'oversize', (0,) * 10000)
        self.assertIsNone(session.cache_get('metadata', 'oversize'))
        self.assertEqual(session.status, Completeness.INCOMPLETE)
        self.assertEqual(session.diagnostics[-1].code, 'BUDGET_EXCEEDED')

    def test_core_imports_with_native_libraries_blocked(self):
        code = '''
import importlib.abc, sys
class Deny(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname.split('.')[0] in {'angr','claripy','pyvex','archinfo','idaapi','networkx'}:
            raise RuntimeError('forbidden native import: '+fullname)
sys.meta_path.insert(0,Deny())
import emtaint.core, emtaint.graph
from emtaint.program_builder import EmProgram
from emtaint.assembly.function import Function
assert EmProgram.get_em_program() is not EmProgram.get_em_program()
print('PASS')
'''
        result = subprocess.run([sys.executable, '-B', '-S', '-c', code], cwd=ROOT,
                                 capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), 'PASS')


if __name__ == '__main__':
    unittest.main()
