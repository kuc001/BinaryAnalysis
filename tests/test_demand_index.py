"""Structural index equivalence for P7 demand without changing P6."""

import unittest
from dataclasses import replace

from emtaint.core import CallSiteId, ProgramPoint
from emtaint.core.contracts import Constant, ValueRef, ValueType
from emtaint.ir.canonical import (
    CallEffect,
    CallFootprint,
    CIRBlock,
    ExternalTarget,
    Compute,
    UnknownEffect,
    ValueOp,
)
from emtaint.analysis.dataflow.demand_index import FunctionDemandIndex
from emtaint.analysis.dataflow.legacy_demand import LegacyDemand
from emtaint.analysis.dataflow.legacy_demand import DemandBudget
from emtaint.analysis.dataflow.demand_query import DemandCompleteness
from emtaint.analysis.dataflow.demand_address import AddressProof
from emtaint.analysis.taint.demand import ProcedureDemand
from emtaint.graph import ControlFlowGraph, FlowEdge, FlowKind

import test_p6_demand as p6


class DemandIndexTests(unittest.TestCase):
    def indexed_demand(self):
        """Build named and wildcard clobbers around ordinary writes."""

        value_type = ValueType.bv(32)
        legacy, function, cfg = p6.DemandTests().make(
            ((p6.put("r4", Constant(1, value_type)),),)
        )
        block = function.blocks[0]
        truth = Constant(True, ValueType.boolean())
        call = CallEffect(
            "o0",
            CallSiteId(ProgramPoint(block.id, 1, 4)),
            ExternalTarget("fixture_call"),
            (),
            (),
            function.abi,
            truth,
            CallFootprint((), (), ("r5",), False, "fixture clobber"),
        )
        unknown = UnknownEffect(
            "o0", "fixture", "fixture wildcard", (), ("*",), False
        )
        effects = (
            block.effects[0],
            call,
            unknown,
            p6.put("r4", Constant(2, value_type)),
        )
        function = replace(
            function,
            blocks=(CIRBlock(block.id, effects),),
        )
        demand = ProcedureDemand(
            function, legacy.port, cfg, legacy.initial
        )
        return demand, block.id, cfg

    def test_indexed_cutoff_matches_frozen_legacy_scan(self):
        demand, block, _ = self.indexed_demand()
        for register in ("r4", "r5", "r6"):
            for cutoff in range(5):
                with self.subTest(register=register, cutoff=cutoff):
                    expected = LegacyDemand.definition_cutoff(
                        demand, block, cutoff, register
                    )
                    self.assertEqual(
                        demand.definition_cutoff(block, cutoff, register),
                        expected,
                    )

    def test_index_is_read_only_and_does_not_create_sse(self):
        demand, block, _ = self.indexed_demand()
        before = len(demand.port.engine.dag.nodes)
        index = demand.function_index
        self.assertIsInstance(index, FunctionDemandIndex)
        self.assertEqual(index.effect_count, 4)
        self.assertEqual(index.value_definitions, demand.defs)
        self.assertEqual(index.calls[block], (1,))
        self.assertEqual(index.definition_cutoff(block, 2, "r5"), 2)
        self.assertEqual(index.definition_cutoff(block, 3, "r6"), 3)
        self.assertEqual(len(demand.port.engine.dag.nodes), before)
        with self.assertRaises(TypeError):
            index.blocks[block] = object()

    def test_indexed_reaching_matches_legacy_result_and_cost(self):
        demand, block, _ = self.indexed_demand()
        demand.steps = 0
        expected = LegacyDemand.reaching(demand, block, 4, "r4")
        legacy_steps = demand.steps
        demand.steps = 0
        demand.reaching_cache.clear()
        actual = demand.reaching(block, 4, "r4")
        self.assertEqual(actual, (frozenset(expected[0]), expected[1]))
        self.assertEqual(demand.steps, legacy_steps)

    def test_entry_remains_a_reaching_source_with_a_back_edge(self):
        demand, block, cfg = self.indexed_demand()
        loop_cfg = ControlFlowGraph(
            cfg.function,
            frozenset(demand.function_index.blocks),
            frozenset((FlowEdge(block, block, FlowKind.JUMP),)),
            block,
        )
        loop = ProcedureDemand(
            demand.function, demand.port, loop_cfg, demand.initial
        )
        expected = LegacyDemand.reaching(loop, block, 0, "r9")
        loop.steps = 0
        actual = loop.reaching(block, 0, "r9")
        self.assertEqual(actual, (frozenset(expected[0]), expected[1]))
        self.assertTrue(actual[1])

    def test_explicit_query_result_distinguishes_budget_incomplete(self):
        demand, block, cfg = self.indexed_demand()
        constant = Constant(7, ValueType.bv(32))
        completed = demand.resolve_value(constant)
        self.assertEqual(completed.completeness, DemandCompleteness.COMPLETE)
        self.assertEqual(
            {demand.port.concrete(value) for value in completed.values},
            {7},
        )
        limited = ProcedureDemand(
            demand.function,
            demand.port,
            cfg,
            demand.initial,
            budget=DemandBudget(steps=0),
        )
        incomplete = limited.resolve_value(constant)
        self.assertEqual(
            incomplete.completeness, DemandCompleteness.INCOMPLETE
        )
        self.assertTrue(incomplete.values)
        self.assertIn("DemandLimit", incomplete.diagnostics[0])
        self.assertEqual(demand.demand_metrics()["queries_completed"], 1)
        self.assertEqual(limited.demand_metrics()["queries_incomplete"], 1)

    def test_address_normalizer_returns_provenance_without_changing_binding(self):
        demand, _, _ = self.indexed_demand()
        constant = Constant(0x1000, ValueType.pointer(32))
        proof = demand.address_normalizer.exact_stack_address(constant)
        self.assertIsInstance(proof, AddressProof)
        self.assertEqual(proof.binding, demand.exact_stack_address(constant))
        self.assertEqual(proof.provenance, ("absolute-constant",))

    def test_query_local_cycles_do_not_leak_between_top_level_queries(self):
        value_type = ValueType.bv(32)
        before = ValueRef("cycle-before", value_type)
        updated = ValueRef("cycle-updated", value_type)
        output = ValueRef("cycle-output", value_type)
        legacy, function, cfg = p6.DemandTests().make(
            (
                (p6.put("r4", Constant(4, value_type)),),
                (
                    p6.get("r4", before),
                    Compute(
                        "o0",
                        updated,
                        ValueOp.ADD,
                        (before, Constant(4, value_type)),
                    ),
                    p6.put("r4", updated),
                ),
                (p6.get("r4", output),),
            ),
            ((0, 1), (1, 1), (1, 2)),
        )
        demand = ProcedureDemand(function, legacy.port, cfg, legacy.initial)
        first = demand.resolve_value(output)
        self.assertFalse(demand.cycles)
        second = demand.resolve_value(output)
        self.assertFalse(demand.cycles)
        self.assertEqual(first.values, second.values)
        self.assertEqual(first.completeness, DemandCompleteness.COMPLETE)

    def test_completed_values_are_independent_of_query_order(self):
        value_type = ValueType.bv(32)
        left = ValueRef("order-left", value_type)
        right = ValueRef("order-right", value_type)

        def make():
            legacy, function, cfg = p6.DemandTests().make(
                ((
                    p6.put("r4", Constant(11, value_type)),
                    p6.get("r4", left),
                    p6.put("r5", Constant(22, value_type)),
                    p6.get("r5", right),
                ),)
            )
            return ProcedureDemand(
                function, legacy.port, cfg, legacy.initial
            )

        forward = make()
        forward_values = {
            "left": forward.port.concrete(
                forward.resolve_value(left).values[0]
            ),
            "right": forward.port.concrete(
                forward.resolve_value(right).values[0]
            ),
        }
        reverse = make()
        reverse_values = {
            "right": reverse.port.concrete(
                reverse.resolve_value(right).values[0]
            ),
            "left": reverse.port.concrete(
                reverse.resolve_value(left).values[0]
            ),
        }
        self.assertEqual(forward_values, reverse_values)

if __name__ == "__main__":
    unittest.main()
