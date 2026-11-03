"""Native regression for the Test-Suite strong-update alias example."""

from pathlib import Path
import unittest

from emtaint.analysis.aliasing import (
    analyze_alias_benchmark,
    parse_alias_expectations,
)


WORKSPACE = Path(__file__).resolve().parents[2]
SOURCE = WORKSPACE / "Test-Suite-master" / "fs_tests" / "strong_update.c"
BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "strong_update.c.elf"
)


@unittest.skipUnless(SOURCE.is_file(), "Test-Suite-master source is unavailable")
class AliasExpectationTests(unittest.TestCase):
    def test_active_markers_preserve_source_lines_and_ignore_absent_may(self):
        expectations = parse_alias_expectations(SOURCE)
        self.assertEqual(
            [(item.kind, item.line, item.left, item.right) for item in expectations],
            [
                ("NOALIAS", 14, "p", "&p1"),
                ("MUSTALIAS", 15, "p", "&q1"),
            ],
        )


@unittest.skipUnless(
    SOURCE.is_file() and BINARY.is_file(),
    "Test-Suite-master strong_update fixture is unavailable",
)
class StrongUpdateAliasTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze_alias_benchmark(SOURCE, BINARY)

    def test_interprocedural_store_is_a_strong_update(self):
        observations = self.report.observations
        self.assertEqual(len(observations), 2)
        self.assertEqual(
            [item.predicted for item in observations],
            ["NOALIAS", "MUSTALIAS"],
        )
        self.assertTrue(all(item.complete for item in observations))
        self.assertTrue(all(item.matched for item in observations))

    def test_binary_sites_and_alias_evidence_are_reported(self):
        first, second = self.report.observations
        self.assertEqual((first.site, second.site), (0x4009D0, 0x4009E3))
        self.assertEqual(first.alias_kinds, ("no_alias",))
        self.assertEqual(second.alias_kinds, ("must_alias",))
        self.assertEqual(self.report.diagnostics, ())


if __name__ == "__main__":
    unittest.main()
