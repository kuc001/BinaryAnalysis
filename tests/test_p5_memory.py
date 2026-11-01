"""Executable memory semantics, independent of native angr/Claripy objects."""
import pathlib
import sys
import unittest
from dataclasses import replace

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from test_p3_contracts import fixture
from emtaint.core import Endian, Completeness, MemoryObject, MemoryObjectId
from emtaint.core.contracts import (ValueType, Assessment, Precision, SemanticBudgets,
    MemoryVersionId, SymbolicExprId, AccessPathId, AccessGraphId)
from emtaint.memory import (Offset, Deref, Index, UnknownOffset, AliasKind,
    ObjectCardinality, ObjectLifetime, SymbolicOp, ReadMemory, WriteMemory,
    UpdateKind, JoinInput, TaintFact)
from emtaint.memory.engine import PythonMemoryEngine, select_memory_engine
from emtaint.memory.access_graph import AccessGraphArena, accepts
from emtaint.memory.policies import BudgetExceeded, BudgetedWorklist
from emtaint.solver.memory_lowering import MemorySolverLowering
from emtaint.solver.lowering import LoweringRequest, LoweringStatus
from emtaint.ir.canonical.wire import dumps, loads


def engine(budgets=SemanticBudgets()):
    _, _, _, origin, scope, arch, root, *_ = fixture()
    e = PythonMemoryEngine(scope, arch, (origin,), budgets)
    e.add_object(MemoryObject(root.object_id, 'test allocation', 64), root,
                 ObjectCardinality.SINGLETON, ObjectLifetime.EXTERNAL, ('explicit fixture singleton',))
    return e, root


class MemoryRuntimeTests(unittest.TestCase):
    def test_offset_deref_and_unknown_index(self):
        e, root = engine()
        a = e.path(root, (Offset(8),), 32, Endian.LITTLE, 'o0')
        p = e.path(root, (Offset(8), Deref(32, 32, Endian.LITTLE)), 32, Endian.LITTLE, 'o0')
        self.assertEqual(a.deref_count, 0)
        self.assertEqual(p.deref_count, 1)
        self.assertEqual(e.location_from_path(a).offset_lower, 8)
        self.assertIsNone(e.location_from_path(p).object_id)
        x = e.dag.symbol('i', ValueType.bv(32), 'o0')
        indexed = e.path(root, (Index(x, 4, 2, 5),), 32, Endian.LITTLE, 'o0')
        self.assertEqual((e.location_from_path(indexed).offset_lower,
                          e.location_from_path(indexed).offset_upper), (8, 20))
        wrap = e.path(root, (Offset(-1),), 8, Endian.LITTLE, 'o0')
        self.assertEqual(e.location_from_path(wrap).offset_lower, 0xffffffff)

    def test_versions_strong_and_false_guard(self):
        e, r = engine(); l = e.location(r, 0, 32, Endian.LITTLE, 'o0')
        m0 = e.initial; x = e.dag.constant(0x12345678, 32, 'o0')
        m1 = e.store(m0, l, x, origin='o0')
        self.assertEqual(e.versions[m1].definition.update, UpdateKind.STRONG)
        before, after = e.load(m0, l), e.load(m1, l)
        self.assertNotEqual(before, after)
        self.assertEqual(e.constant_value(after), 0x12345678)
        m2 = e.store(m1, l, e.dag.constant(9, 32, 'o0'), e.dag.boolean(False, 'o0'), 'o0')
        self.assertEqual(e.constant_value(e.load(m2, l)), 0x12345678)
        self.assertEqual(e.resolve_definition(e.reads[-1]).definitions, (m1,))

    def test_partial_overlap_endian_and_unaligned(self):
        for endian in Endian:
            e, r = engine(); l = e.location(r, 0, 32, endian, 'o0')
            m = e.store(e.initial, l, e.dag.constant(0x11223344, 32, 'o0'), origin='o0')
            mid = e.location(r, 1, 16, endian, 'o0')
            m = e.store(m, mid, e.dag.constant(0x2233, 16, 'o0'), origin='o0')
            # LE writes bytes 33,22; BE writes 22,33.
            self.assertEqual(e.constant_value(e.load(m, l)), 0x11223344)
            opposite = Endian.BIG if endian == Endian.LITTLE else Endian.LITTLE
            m = e.store(m, replace(mid, endian=opposite), e.dag.constant(0x2233, 16, 'o0'), origin='o0')
            self.assertEqual(e.constant_value(e.load(m, l)), 0x11332244)

    def test_may_alias_preserves_both_definitions(self):
        e, r = engine(); p = e.location(r, 0, 8, Endian.LITTLE, 'o0')
        qroot = replace(r, object_id=MemoryObjectId.argument(e.scope.function, 1, e.scope.context))
        e.add_object(MemoryObject(qroot.object_id, 'may alias argument', 64), qroot,
            ObjectCardinality.UNKNOWN, ObjectLifetime.EXTERNAL, ('no disjointness evidence',))
        q = e.location(qroot, 0, 8, Endian.LITTLE, 'o0')
        self.assertEqual(e.resolve_alias(e.initial, p, q).kind, AliasKind.MAY)
        m1 = e.store(e.initial, p, e.dag.constant(7, 8, 'o0'), origin='o0')
        m2 = e.store(m1, q, e.dag.constant(9, 8, 'o0'), origin='o0')
        self.assertEqual(e.versions[m2].definition.update, UpdateKind.WEAK)
        read = e.load(m2, p)
        self.assertEqual(set(e.possible_constants(read)), {7, 9})
        self.assertEqual(set(e.resolve_definition(e.reads[-1]).definitions), {m1, m2})
        self.assertEqual(e.constant_value(e.load(m1, p)), 7)

    def test_singleton_summary_and_noalias_evidence(self):
        e, r = engine(); p = e.location(r, 0, 8, Endian.LITTLE, 'o0')
        self.assertEqual(e.resolve_alias(e.initial, p, p).kind, AliasKind.MUST)
        other = e.location(r, 1, 8, Endian.LITTLE, 'o0')
        self.assertEqual(e.resolve_alias(e.initial, p, other).kind, AliasKind.NO)
        r2 = replace(r, object_id=MemoryObjectId.stack(e.scope.function, e.scope.context, 'other-frame'))
        e.add_object(MemoryObject(r2.object_id, 'frame', 64), r2, ObjectCardinality.SINGLETON,
                     ObjectLifetime.FRAME, ('frame exists',))
        q = e.location(r2, 0, 8, Endian.LITTLE, 'o0')
        self.assertEqual(e.resolve_alias(e.initial, p, q).kind, AliasKind.MAY)
        e.prove_disjoint(r.object_id, r2.object_id, 'fixture proves nonoverlapping storage')
        self.assertEqual(e.resolve_alias(e.initial, p, q).kind, AliasKind.NO)

    def test_join_guard_havoc_and_pointer_rewrite(self):
        e, r = engine(); p = e.location(r, 8, 32, Endian.LITTLE, 'o0')
        a = e.store(e.initial, p, e.dag.constant(16, 32, 'o0'), origin='o0')
        b = e.store(a, p, e.dag.constant(24, 32, 'o0'), origin='o0')
        self.assertEqual(e.constant_value(e.load(a, p)), 16)
        self.assertEqual(e.constant_value(e.load(b, p)), 24)
        g = e.dag.symbol('branch', ValueType.boolean(), 'o0')
        ng = e.dag.operation(SymbolicOp.NOT, ValueType.boolean(), (g,), 'o0')
        j = e.join((JoinInput(a, g), JoinInput(b, ng)), 'o0')
        self.assertEqual(set(e.possible_constants(e.load(j, p))), {16, 24})
        h = e.havoc(b, ('*',), 'external call', 'o0')
        self.assertIsNone(e.constant_value(e.load(h, p)))
        self.assertEqual(e.snapshot().assessment.status, Completeness.INCOMPLETE)
        unaffected = e.havoc(b, ('global',), 'global-only call', 'o0')
        self.assertEqual(e.constant_value(e.load(unaffected, p)), 24)

    def test_dag_sharing_lazy_substitute_and_session_isolation(self):
        e, _ = engine(); d = e.dag
        x = d.symbol('x', ValueType.bv(32), 'o0'); one = d.constant(1, 32, 'o0')
        expr = d.operation(SymbolicOp.ADD, ValueType.bv(32), (x, one), 'o0')
        self.assertEqual(expr, d.operation(SymbolicOp.ADD, ValueType.bv(32), (x, one), 'o0'))
        lazy = d.substitute(expr, {x: d.constant(7, 32, 'o0')})
        self.assertEqual(d.materialize(lazy), d.materialize(lazy))
        self.assertEqual(d.constant_value(d.materialize(lazy)), 8)
        self.assertLess(len(d.nodes), 9)
        other, _ = engine(); self.assertEqual(len(other.dag.nodes), 0)

    def test_serialized_runtime_replays_values_facts_and_versions(self):
        e, r = engine(); p = e.path(r, (Offset(0),), 32, Endian.LITTLE, 'o0')
        l = e.location_from_path(p); m = e.store(e.initial, l, e.dag.constant(42, 32, 'o0'), origin='o0')
        g = e.dag.boolean(True, 'o0'); v = e.load(m, l)
        e.add_taint(TaintFact('source', r, p.id, None, e.scope.context, m, g,
            'may-source-to-sink', 'o0', ('Source(arg)', 'Sink candidate'),
            Assessment(Completeness.COMPLETE, Precision.OVER_APPROX, ('may fact only',), diagnostics=())))
        self.assertEqual(e.constant_value(v), 42)
        snapshot = e.snapshot(); restored = PythonMemoryEngine.from_snapshot(loads(dumps(snapshot)))
        self.assertEqual(restored.snapshot(), snapshot)
        self.assertEqual(restored.constant_value(v), 42)
        self.assertEqual(restored.snapshot(), snapshot)
        self.assertEqual(restored.sink_candidates(), e.sink_candidates())
        self.assertFalse(e.sink_candidates()[0]['confirmed'])

    def test_default_engine_is_explicit_legacy_reference(self):
        legacy = object(); self.assertIs(select_memory_engine(legacy=legacy), legacy)
        e, _ = engine(); self.assertIs(select_memory_engine('apg', apg=e), e)
        with self.assertRaises(ValueError): select_memory_engine('rust')
        with self.assertRaises(ValueError): select_memory_engine()

    def test_budget_failures_are_explicit_and_independent(self):
        e, r = engine(replace(SemanticBudgets(), sse_nodes=1))
        e.dag.constant(1, 8, 'o0')
        with self.assertRaises(BudgetExceeded) as error: e.dag.constant(2, 8, 'o0')
        self.assertEqual(error.exception.dimension, 'sse_nodes')
        self.assertEqual(error.exception.assessment.status, Completeness.INCOMPLETE)
        work = BudgetedWorklist(replace(SemanticBudgets(), worklist_iterations=4))
        with self.assertRaises(BudgetExceeded): work.run((0,), lambda x: (x + 1,))
        self.assertGreater(len(work.pending), 0)


class APGRuntimeTests(unittest.TestCase):
    def test_linked_list_10_100_1000_preserves_language(self):
        e, r = engine(); pattern = (Offset(8), Deref(32, 32, Endian.LITTLE))
        for n in (10, 100, 1000):
            arena = AccessGraphArena(e.scope, e.budgets)
            path = e.path(r, pattern * n + (Offset(4),), 32, Endian.LITTLE, 'o0')
            graph = arena.intern(path, e.origins[0].point)
            self.assertTrue(accepts(graph, path.segments))
            self.assertTrue(accepts(graph, pattern * (n+1) + (Offset(4),)))
            self.assertLessEqual(len(graph.nodes), 5)
            self.assertEqual(graph.summaries[0].soundness, Completeness.COMPLETE)
            self.assertEqual(graph.assessment.precision, Precision.OVER_APPROX)
            self.assertEqual(graph, loads(dumps(graph)))

    def test_tree_doubly_linked_and_budget_fallback(self):
        e, r = engine()
        for pattern in ((Offset(8), Deref(32,32,Endian.LITTLE), Offset(16), Deref(32,32,Endian.LITTLE)),
                        (Offset(8), Deref(32,32,Endian.LITTLE), Offset(-8), Deref(32,32,Endian.LITTLE))):
            path = e.path(r, pattern*100, 32, Endian.LITTLE, 'o0')
            graph = AccessGraphArena(e.scope, e.budgets).intern(path, e.origins[0].point)
            self.assertTrue(accepts(graph, path.segments))
        tiny = AccessGraphArena(e.scope, replace(e.budgets, apg_nodes=1))
        with self.assertRaises(BudgetExceeded): tiny.intern(e.path(r,(Offset(1),Offset(2)),32,Endian.LITTLE,'o0'),e.origins[0].point)


if __name__ == '__main__':
    unittest.main()
