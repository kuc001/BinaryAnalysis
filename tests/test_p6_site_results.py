"""Typed iCall site-result contracts and legacy artifact compatibility."""

import unittest

from emtaint.analysis.controlflow.legacy_tables import LegacyTableEvidence
from emtaint.core.contracts import Assessment
from emtaint.orchestration.legacy_cir_search import CallSiteAnalysisResult


class CallSiteAnalysisResultTests(unittest.TestCase):
    """Keep the typed evidence boundary strict and serialization-compatible."""

    @staticmethod
    def _table_evidence() -> LegacyTableEvidence:
        """Build one deterministic table-candidate evidence record."""

        return LegacyTableEvidence(
            rule="Collector.calculate_icall_targets",
            read_type="func",
            expression="expr-1",
            loader_version="memory-1",
            indices_examined=2,
            targets=(0x2000, 0x2004),
            unknown_remainder=True,
            maximum_address=0x3000,
            nested_substitutions=0,
            provenance="fixture",
        )

    def test_analyzed_site_preserves_frozen_coverage_shape(self) -> None:
        result = CallSiteAnalysisResult(
            site=0x1100,
            origin="origin-1",
            targets=(0x2000, 0x2004),
            evidence=(self._table_evidence(),),
            unknown_remainder=True,
            assessment=Assessment(),
            demand_steps=17,
            cfg_reachable=True,
            expressions=("expr-1",),
            rule_ids=("rule-1",),
            memory_version="memory-1",
        )

        self.assertEqual(
            result.to_legacy_dict(),
            {
                "site": 0x1100,
                "origin": "origin-1",
                "cfg_reachable": True,
                "targets": [0x2000, 0x2004],
                "expressions": ["expr-1"],
                "evidence": [self._table_evidence().to_legacy_dict()],
                "unknown_remainder": True,
                "rule_ids": ["rule-1"],
                "memory_version": "memory-1",
            },
        )
        normalized = result.to_evidence_dict()
        self.assertEqual(normalized["demand_steps"], 17)
        self.assertIn("assessment", normalized)

    def test_classified_return_preserves_legacy_variant(self) -> None:
        result = CallSiteAnalysisResult(
            site=0x1100,
            origin="origin-return",
            targets=(),
            evidence=(),
            unknown_remainder=False,
            assessment=Assessment.complete(),
            demand_steps=3,
            cfg_reachable=True,
            classification="IDA annotation / CIR native return",
        )

        self.assertEqual(
            result.to_legacy_dict(),
            {
                "site": 0x1100,
                "classification": "IDA annotation / CIR native return",
                "origin": "origin-return",
                "cfg_reachable": True,
                "targets": [],
            },
        )

    def test_invalid_target_order_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            CallSiteAnalysisResult(
                site=0x1100,
                origin="origin-1",
                targets=(0x2004, 0x2000),
                evidence=(),
                unknown_remainder=True,
                assessment=Assessment(),
                demand_steps=1,
                cfg_reachable=True,
                memory_version="memory-1",
            )


if __name__ == "__main__":
    unittest.main()
