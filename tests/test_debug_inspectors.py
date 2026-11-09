"""D2 bounded, read-only inspector behavior."""

import unittest

from emtaint.core.contracts import Constant, ValueRef, ValueType
from emtaint.ir.canonical import Compute, ValueOp
from emtaint.memory.state import SymbolicOp

import test_p6_demand as p6


class DebugInspectorTests(unittest.TestCase):
    def make_demand(self):
        value_type = ValueType.bv(32)
        source = ValueRef("debug-source", value_type)
        result = ValueRef("debug-result", value_type)
        demand, _, _ = p6.DemandTests().make(
            ((
                Compute("o0", source, ValueOp.COPY, (Constant(7, value_type),)),
                Compute(
                    "o0",
                    result,
                    ValueOp.ADD,
                    (source, source),
                ),
            ),)
        )
        return demand, source, result

    def test_explain_value_uses_real_definition_and_origin(self):
        demand, _, result = self.make_demand()
        explanation = demand.debug.explain_value(result)
        self.assertIn("Compute", explanation)
        self.assertIn("block=0x0", explanation)
        self.assertIn("instruction=0x0", explanation)
        self.assertIn("debug-source", explanation)

    def test_expression_limits_and_shared_nodes_are_explicit(self):
        demand, _, _ = self.make_demand()
        engine = demand.port.engine
        origin = engine.origins[0].id
        leaf = engine.dag.symbol("entry:r4", ValueType.bv(32), origin)
        root = engine.dag.operation(
            SymbolicOp.ADD, ValueType.bv(32), (leaf, leaf), origin
        )
        explanation = demand.debug.explain_expr(root, max_depth=3)
        self.assertIn("add", explanation)
        self.assertIn("meaning='entry:r4'", explanation)
        self.assertIn("(shared)", explanation)
        limited = demand.debug.explain_expr(root, max_depth=0)
        self.assertIn("depth limit 0", limited)

    def test_demand_explanation_reads_cache_without_new_queries(self):
        demand, _, result = self.make_demand()
        before = (
            demand.steps,
            demand.port.engine.alias_queries,
            demand.port.engine.definition_queries,
            len(demand.port.engine.dag.nodes),
        )
        unavailable = demand.debug.explain_demand_value(demand, result)
        self.assertIn("will not execute", unavailable)
        roots = demand.value(result)
        after_analysis = (
            demand.steps,
            demand.port.engine.alias_queries,
            demand.port.engine.definition_queries,
            len(demand.port.engine.dag.nodes),
        )
        explanation = demand.debug.explain_demand_value(demand, result)
        after_inspection = (
            demand.steps,
            demand.port.engine.alias_queries,
            demand.port.engine.definition_queries,
            len(demand.port.engine.dag.nodes),
        )
        self.assertTrue(roots)
        self.assertIn("Roots: 1", explanation)
        self.assertEqual(after_inspection, after_analysis)
        self.assertEqual(before[1:3], after_inspection[1:3])

    def test_lazy_debug_mode_preserves_analysis_result(self):
        normal, _, normal_result = self.make_demand()
        debug, _, debug_result = self.make_demand()
        _ = debug.debug.explain_value(debug_result)
        normal_roots = normal.value(normal_result)
        debug_roots = debug.value(debug_result)
        self.assertEqual(
            [normal.port.concrete(root) for root in normal_roots],
            [debug.port.concrete(root) for root in debug_roots],
        )
        self.assertEqual(normal.steps, debug.steps)
        self.assertEqual(normal.port.calls, debug.port.calls)


if __name__ == "__main__":
    unittest.main()
