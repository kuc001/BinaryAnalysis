from collections import Counter
import io
import json
from pathlib import Path
import sys
import types
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
from legacy_observer import expression_metrics, classify_query, LegacyObserver
from p0b_v5_collect import observation_plan


class Node:
    def __init__(self, op, *args):
        self.op, self.args = op, args


class ObserverTests(unittest.TestCase):
    def test_unique_and_expanded_counts_with_shared_load(self):
        p = Node("BVS", "p")
        ld = Node("Load", p)
        root = Node("Add", ld, ld)
        result = expression_metrics(root, Node)
        self.assertEqual((result["unique"], result["expanded"]), (3, 5))
        self.assertEqual((result["load_occurrences"], result["load_depth"]), (2, 1))

    def test_deep_chain_does_not_require_python_recursion(self):
        root = Node("BVS", "p")
        for _ in range(1000):
            root = Node("Load", root)
        result = expression_metrics(root, Node)
        self.assertEqual((result["unique"], result["load_depth"]), (1001, 1000))

    def test_metrics_budget_and_cycle_are_explicit(self):
        node = Node("Load", Node("BVS", "p"))
        with self.assertRaises(ValueError):
            expression_metrics(node, Node, node_budget=1)
        node.args = (node,)
        with self.assertRaises(ValueError):
            expression_metrics(node, Node)

    def test_unknown_false_not_reclassified_as_unsat(self):
        self.assertEqual(classify_query([{"status": "unknown", "reason": "timeout"}], False), "TIMEOUT")
        self.assertEqual(classify_query([{"status": "unknown", "reason": "incomplete"}], False), "UNKNOWN")
        self.assertEqual(classify_query([], False), "FALSE_WITHOUT_RAW_CHECK")
        self.assertEqual(classify_query([{"status": "unsat", "reason": None}], False), "UNSAT")

    def test_enumeration_end_unsat_is_not_query_unsat(self):
        raw = [{'status': 'sat'}, {'status': 'unsat'}]
        self.assertEqual(classify_query(raw, (7,), method='eval'), 'SAT')
        self.assertEqual(classify_query(raw, False), 'UNSAT')
        self.assertEqual(classify_query(raw + [{'status': 'unknown', 'reason': 'timeout'}], (7,), method='eval'), 'TIMEOUT')

    def test_real_source_plan_is_fingerprinted_and_has_specific_gates(self):
        plan = observation_plan()
        self.assertEqual(len(plan["source_hashes"]), 3)
        self.assertTrue(any(g["ls_threshold"] == 2 for g in plan["gates"]))
        self.assertTrue(any("MAX_LOOPS" in g["condition"] for g in plan["gates"]))
        self.assertTrue(any("FUNC_MAX_TIMES" in g["condition"] for g in plan["gates"]))
        self.assertTrue(all(g["body_line"] > g["test_start"] for g in plan["gates"]))

    def test_gate_classifies_actual_short_circuit_without_rechecking_ast(self):
        obs = LegacyObserver.__new__(LegacyObserver)
        gate = {"id": "g", "ls_threshold": 5, "test_start": 40, "test_end": 41}
        obs.lookup = {("source", 10): {50: [gate]}}
        obs.frame_state = {}
        obs.gates = {"g": {"hits": 0, "aptr_limit_hits": 0, "other_or_short_circuit_hits": 0,
                           "input_fact_skip_events": 0, "lost_output_facts": None}}
        frame = types.SimpleNamespace(f_code=types.SimpleNamespace(co_filename="source", co_firstlineno=10),
                                      f_lineno=50, f_locals={"trace_expr": object()})
        obs._trace(frame, "call", None)
        obs.frame_state[id(frame)]["ls"] = (41, 6)
        obs._trace(frame, "line", None)
        obs.frame_state[id(frame)]["ls"] = None
        obs._trace(frame, "line", None)
        self.assertEqual(obs.gates["g"]["aptr_limit_hits"], 1)
        self.assertEqual(obs.gates["g"]["other_or_short_circuit_hits"], 1)
        self.assertIsNone(obs.gates["g"]["lost_output_facts"])
        obs._trace(frame, "return", None)
        self.assertFalse(obs.frame_state)

    def test_query_wrapper_calls_once_and_preserves_return_and_exception(self):
        obs = LegacyObserver.__new__(LegacyObserver)
        obs.saved, obs.query_stack, obs.errors = [], [], []
        obs.query_count, obs.counts, obs.status_counts = 0, Counter(), Counter()
        obs.base, obs.events = Node, io.StringIO()
        calls = []
        class Solver:
            constraints = []
            timeout = 1
            def satisfiable(self):
                calls.append(1)
                obs.query_stack[-1]["raw"].append({"status": "unknown", "reason": "timeout"})
                return False
        obs._wrap_query(Solver, "satisfiable", "fixture")
        self.assertIs(Solver().satisfiable(), False)
        self.assertEqual(len(calls), 1)
        self.assertEqual(json.loads(obs.events.getvalue())["status"], "TIMEOUT")
        error = RuntimeError("same error")
        class Bad:
            constraints = []
            def satisfiable(self):
                raise error
        obs._wrap_query(Bad, "satisfiable", "fixture")
        with self.assertRaises(RuntimeError) as caught:
            Bad().satisfiable()
        self.assertIs(caught.exception, error)
        self.assertFalse(obs.query_stack)


if __name__ == "__main__":
    unittest.main()
