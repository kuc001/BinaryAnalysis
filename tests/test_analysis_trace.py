"""D3 structured trace, equivalence, and evaluator characterization."""

from pathlib import Path
import unittest
import uuid

from emtaint.analysis.controlflow.legacy_tables import LegacyTableCollector
from emtaint.analysis_debugging import AnalysisTraceRecorder
from emtaint.core import Endian
from emtaint.core.contracts import Constant, ValueRef, ValueType
from emtaint.ir.canonical import Compute, LoadEffect, ValueOp
from emtaint.memory import SymbolicOp

import test_p6_demand as p6


class AnalysisTraceTests(unittest.TestCase):
    def make_compute(self):
        value_type = ValueType.bv(32)
        source = ValueRef("trace-source", value_type)
        result = ValueRef("trace-result", value_type)
        demand, _, _ = p6.DemandTests().make(
            ((
                Compute("o0", source, ValueOp.COPY, (Constant(7, value_type),)),
                Compute(
                    "o0", result, ValueOp.ADD, (source, Constant(3, value_type))
                ),
            ),)
        )
        return demand, result

    def test_trace_mode_is_result_equivalent_and_explains_rule(self):
        normal, normal_value = self.make_compute()
        traced, traced_value = self.make_compute()
        recorder = traced.enable_debug_trace()
        normal_roots = normal.value(normal_value)
        traced_roots = traced.value(traced_value)
        self.assertEqual(
            [normal.port.concrete(root) for root in normal_roots],
            [traced.port.concrete(root) for root in traced_roots],
        )
        self.assertEqual(normal.steps, traced.steps)
        self.assertEqual(normal.port.calls, traced.port.calls)
        rules = {event.rule for event in recorder.events()}
        self.assertIn("DEMAND_COMPUTE", rules)
        self.assertIn("SSE_OPERATION_ADD", rules)
        explanation = traced.debug.explain_demand_value(traced, traced_value)
        self.assertIn("Rule #", explanation)
        self.assertIn("DEMAND_COMPUTE", explanation)

    def test_memory_query_trace_uses_existing_query_result(self):
        value = ValueRef("trace-load", ValueType.bv(32))
        demand, _, _ = p6.DemandTests().make(
            ((LoadEffect(
                "o0",
                value,
                Constant(0x1000, ValueType.pointer(32)),
                32,
                Endian.LITTLE,
                Constant(True, ValueType.boolean()),
            ),),)
        )
        recorder = demand.enable_debug_trace()
        roots = demand.value(value)
        before = dict(demand.port.calls)
        explanation = demand.debug.explain_expr(roots[0])
        self.assertIn("memory_read", explanation)
        self.assertEqual(demand.port.calls, before)
        rules = {event.rule for event in recorder.events()}
        self.assertIn("MEMORY_READ_QUERY", rules)
        self.assertIn("DEMAND_MEMORY_LOAD", rules)

    def test_recorder_bound_filter_and_jsonl_export(self):
        recorder = AnalysisTraceRecorder(enabled=True, max_events=1)
        recorder.record("RULE", 0, inputs=("a",), outputs=("b",))
        recorder.record("RULE", 0, inputs=("b",), outputs=("c",))
        self.assertEqual(len(recorder.events()), 1)
        self.assertEqual(recorder.dropped, 1)
        destination = Path(".debug") / (
            "test-analysis-trace-" + uuid.uuid4().hex + ".jsonl"
        )
        try:
            recorder.export_jsonl(destination)
            self.assertIn('"rule": "RULE"', destination.read_text(encoding="utf8"))
        finally:
            destination.unlink(missing_ok=True)

    def test_refactored_evaluator_matches_frozen_truth_table(self):
        demand, _ = self.make_compute()
        collector = LegacyTableCollector(demand, lambda _: False, lambda _: False)
        engine = demand.port.engine
        origin = engine.origins[0].id
        index = engine.dag.symbol("i", ValueType.bv(32), origin)
        one = engine.dag.constant(1, 32, origin)
        root = engine.dag.operation(
            SymbolicOp.ADD, ValueType.bv(32), (index, one), origin
        )
        for value in (0, 1, 0xFFFFFFFF):
            with self.subTest(value=value):
                self.assertEqual(
                    collector.evaluate(root, value),
                    (value + 1) % (1 << 32),
                )


if __name__ == "__main__":
    unittest.main()
