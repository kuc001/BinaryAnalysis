"""P7.1 source and sink identities from the active old procedure dispatch."""

import unittest
from dataclasses import replace

from emtaint.core.contracts import Constant, ValueRef, ValueType
from emtaint.ir.canonical import CIRBlock
from emtaint.analysis.taint.demand import LegacyTaintDemand
from emtaint.procedures.legacy import RULES, lookup
import test_p7_demand as fixtures


class LegacyRuleRegistryTests(unittest.TestCase):
    def test_rule_identity_is_unique_and_exact(self):
        self.assertEqual(len({rule.rule_id for rule in RULES}), len(RULES))
        self.assertIsNone(lookup("Recv"))
        self.assertIsNone(lookup("strcpy@@GLIBC"))
        self.assertEqual(lookup("recv").rule_id, "legacy-procedure/recv")

    def test_source_argument_and_return_positions(self):
        expected = {
            "BIO_read": (1, 0, (2,)),
            "BIO_gets": (1, 0, (2,)),
            "recv": (1, 0, (2,)),
            "recvfrom": (1, 0, (2,)),
            "read": (1, 0, (2,)),
            "fgets": (0, 2, (1,)),
            "fread": (0, 3, (1, 2)),
        }
        for name, (destination, source, lengths) in expected.items():
            with self.subTest(name=name):
                rule = lookup(name)
                self.assertEqual(rule.operation, "source_buffer")
                self.assertEqual((rule.destination, rule.source, rule.lengths),
                                 (destination, source, lengths))
        self.assertEqual(lookup("getenv").operation, "source_return")
        self.assertEqual(lookup("getenv").source, 0)
        self.assertEqual((lookup("FCGX_GetParam").operation,
                          lookup("FCGX_GetParam").source), ("source_return", 0))
        self.assertEqual((lookup("hdf_get_value").operation,
                          lookup("hdf_get_value").source), ("source_return", 1))

    def test_ssl_read_keeps_separate_old_trace_semantics(self):
        rule = lookup("SSL_read")
        self.assertEqual(rule.operation, "legacy_trace_source")
        self.assertEqual((rule.destination, rule.source, rule.lengths),
                         (1, 0, (2,)))
        self.assertIn("without taint_source ID", rule.provenance)

    def test_command_and_copy_bind_only_the_old_operands(self):
        for name in ("system", "popen", "_system"):
            with self.subTest(name=name):
                self.assertEqual((lookup(name).operation, lookup(name).source),
                                 ("command", 0))
        self.assertEqual((lookup("execve").operation, lookup("execve").source),
                         ("command_argv", 1))
        for name in ("strcpy", "strcat", "strncpy", "strncat", "strlcpy",
                     "memcpy", "memmove"):
            with self.subTest(name=name):
                self.assertEqual((lookup(name).operation, lookup(name).destination,
                                  lookup(name).source), ("copy", 0, 1))
        self.assertEqual(lookup("strlcpy").lengths, (2,))
        self.assertEqual((lookup("vsnprintf").operation,
                          lookup("vsnprintf").source,
                          lookup("vsnprintf").format_index),
                         ("format_output_va_list", 3, 2))

    def test_source_call_has_initial_fact_without_a_downstream_sink(self):
        demand, _ = fixtures.TaintDemandTests().make((("recv", (0, 0x1000, 16, 0), True),))
        demand.analyze()
        self.assertTrue(any(binding.source_site == 0
                            for binding in demand.source_bindings.values()))
        self.assertTrue(demand.port.engine.facts)

    def test_false_guard_does_not_register_initial_source(self):
        demand, _ = fixtures.TaintDemandTests().make((("recv", (0, 0x1000, 16, 0), False),))
        demand.analyze()
        self.assertFalse(demand.source_bindings)

    def test_unresolved_vsnprintf_format_is_explicitly_incomplete(self):
        demand, block = fixtures.TaintDemandTests().make((("vsnprintf", (0x2000, 16, 0x1000, 0x3000), True),))
        call=demand.function.blocks[0].effects[0]
        fmt=ValueRef("formal-format",ValueType.pointer(32))
        function=replace(demand.function,values=(fmt,),blocks=(
            CIRBlock(block,(replace(call,arguments=call.arguments[:2]+(fmt,)+call.arguments[3:]),)),))
        demand=LegacyTaintDemand(function,demand.port,demand.cfg,demand.demand.initial)
        summary = demand.analyze()
        self.assertTrue(any("va_list" in str(item) for item in summary.pending))

    def test_legacy_ssl_trace_remains_incomplete_without_an_invented_source_id(self):
        demand, _ = fixtures.TaintDemandTests().make((("SSL_read", (0, 0x1000, 16), True),))
        summary = demand.analyze()
        self.assertFalse(demand.source_bindings)
        self.assertTrue(any("no Source ID" in str(item) for item in summary.pending))

    def test_return_source_is_registered_without_a_sink(self):
        demand, block = fixtures.TaintDemandTests().make((("getenv", (0x1000,), True),))
        call=demand.function.blocks[0].effects[0]
        returned=ValueRef("getenv-return-fact",ValueType.bv(32))
        function=replace(demand.function,values=(returned,),blocks=(
            CIRBlock(block,(replace(call,results=(returned,)),)),))
        demand=LegacyTaintDemand(function,demand.port,demand.cfg,demand.demand.initial)
        demand.analyze()
        self.assertTrue(any(binding.source_site == 0
                            for binding in demand.source_bindings.values()))
        fact=demand.scalar_source_facts[returned.id]
        self.assertEqual((fact.value_id,fact.point,fact.context,fact.origin),
            (returned.id,call.site.point,demand.port.scope.context,call.origin))
        self.assertIsNotNone(fact.guard)
        self.assertFalse(fact.uncertain)

    def test_return_source_fact_keeps_unknown_guard_and_skips_false_call(self):
        for active in (None,False):
            with self.subTest(active=active):
                original,block=fixtures.TaintDemandTests().make(
                    (("getenv",(0x1000,),True),))
                call=original.function.blocks[0].effects[0]
                returned=ValueRef("guarded-getenv-return",ValueType.bv(32))
                condition=ValueRef("getenv-guard",ValueType.boolean())
                guard=condition if active is None else Constant(False,ValueType.boolean())
                function=replace(original.function,
                    values=(returned,condition),blocks=(CIRBlock(block,(
                        replace(call,results=(returned,),guard=guard),)),))
                demand=LegacyTaintDemand(function,original.port,original.cfg,
                                         original.demand.initial)
                demand.analyze()
                if active is None:
                    fact=demand.scalar_source_facts[returned.id]
                    self.assertTrue(fact.uncertain)
                    self.assertEqual(fact.point,call.site.point)
                else:
                    self.assertFalse(demand.scalar_source_facts)

    def test_fread_source_extent_multiplies_size_and_count(self):
        demand, _ = fixtures.TaintDemandTests().make((("fread", (0x1000, 4, 8, 0), True),))
        demand.analyze()
        self.assertTrue(any(binding.constraints == (32,)
                            for binding in demand.source_bindings.values()))

    def test_fgets_source_uses_buffer_and_length_slots(self):
        demand, _ = fixtures.TaintDemandTests().make((("fgets", (0x1000, 24, 0), True),))
        demand.analyze()
        self.assertTrue(any(binding.constraints == (24,)
                            for binding in demand.source_bindings.values()))

    def test_strlcpy_is_a_bounded_copy_requirement(self):
        demand, _ = fixtures.TaintDemandTests().make((
            ("recv", (0, 0x1000, 16, 0), True),
            ("strlcpy", (0x2000, 0x1000, 8), True)))
        summary = demand.analyze()
        sink = next(item for item in summary.sinks if item.name == "strlcpy")
        self.assertEqual(sink.weak_kind, "copy_length")
        self.assertTrue(any(dep.kind == "source" for dep in sink.dependencies))


if __name__ == "__main__":
    unittest.main()
