"""Native regression for the Test-Suite strong-update alias example."""

from pathlib import Path
import sys
import unittest

from scripts.httpd_baseline_check import check_baseline

from scripts.alias_benchmark_analysis import (
    analyze_alias_benchmark,
    matches_expectation,
    parse_alias_expectations,
)
from scripts.alias_suite_manifest import build_alias_suite_manifest
from scripts.alias_suite_runner import _execute, evaluate_sample


WORKSPACE = Path(__file__).resolve().parents[2]
SOURCE = WORKSPACE / "Test-Suite-master" / "fs_tests" / "strong_update.c"
BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "strong_update.c.elf"
)
SIMPLE_SOURCE = WORKSPACE / "Test-Suite-master" / "fs_tests" / "simple_1.c"
SIMPLE_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "simple_1.c.elf"
)
ARRAY_ONE_SOURCE = (
    WORKSPACE / "Test-Suite-master" / "fs_tests" / "array_alias_1.c"
)
ARRAY_ONE_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "array_alias_1.c.elf"
)
ARRAY_SIX_SOURCE = (
    WORKSPACE / "Test-Suite-master" / "fs_tests" / "array_alias_6.c"
)
ARRAY_SIX_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "test_cases_bc"
    / "fs_tests"
    / "array_alias_6.c.elf"
)
GLOBAL_ONE_SOURCE = (
    WORKSPACE / "Test-Suite-master" / "fs_tests" / "global_1.c"
)
GLOBAL_ONE_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "global_1.c.elf"
)
GLOBAL_TWO_SOURCE = (
    WORKSPACE / "Test-Suite-master" / "fs_tests" / "global_2.c"
)
GLOBAL_TWO_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "global_2.c.elf"
)
GLOBAL_FOUR_SOURCE = (
    WORKSPACE / "Test-Suite-master" / "fs_tests" / "global_4.c"
)
GLOBAL_FOUR_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "global_4.c.elf"
)
RETURN_SOURCE = WORKSPACE / "Test-Suite-master" / "fs_tests" / "return.c"
RETURN_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "test_cases_bc"
    / "fs_tests"
    / "return.c.elf"
)
FUNCTION_POINTER_SOURCE = (
    WORKSPACE / "Test-Suite-master" / "fs_tests" / "function_pointer.c"
)
FUNCTION_POINTER_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "function_pointer.c.elf"
)
FUNCTION_POINTER_TWO_SOURCE = (
    WORKSPACE / "Test-Suite-master" / "fs_tests" / "function_pointer_2.c"
)
FUNCTION_POINTER_TWO_BINARY = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "function_pointer_2.c.elf"
)


@unittest.skipUnless(SOURCE.is_file(), "Test-Suite-master source is unavailable")
class AliasExpectationTests(unittest.TestCase):
    def test_complete_must_refines_may_assertion_only(self):
        self.assertTrue(matches_expectation("MAYALIAS", "MUSTALIAS", True))
        self.assertFalse(matches_expectation("MAYALIAS", "MUSTALIAS", False))
        self.assertFalse(matches_expectation("MUSTALIAS", "MAYALIAS", True))
        self.assertFalse(matches_expectation("NOALIAS", "MUSTALIAS", True))

    def test_active_markers_preserve_source_lines_and_ignore_absent_may(self):
        expectations = parse_alias_expectations(SOURCE)
        self.assertEqual(
            [(item.kind, item.line, item.left, item.right) for item in expectations],
            [
                ("NOALIAS", 14, "p", "&p1"),
                ("MUSTALIAS", 15, "p", "&q1"),
            ],
        )

    def test_four_suite_manifest_freezes_sources_markers_and_binary_fallback(self):
        manifest = build_alias_suite_manifest(WORKSPACE)
        self.assertEqual(len(manifest["samples"]), 172)
        self.assertEqual(manifest["required_marker_count"], 490)
        self.assertEqual(manifest["xfail_marker_count"], 9)
        self.assertEqual(manifest["smoke_only_count"], 6)
        fallback = [
            item for item in manifest["samples"]
            if item["binary_origin"] == "test_cases_bc"
        ]
        self.assertEqual(
            [(item["suite"], item["sample"]) for item in fallback],
            [
                ("fs_tests", "array_alias_6.c"),
                ("fs_tests", "return.c"),
            ],
        )
        returned = next(
            item for item in manifest["samples"]
            if item["suite"] == "fs_tests" and item["sample"] == "return.c"
        )
        self.assertEqual(returned["markers"]["NOALIAS"], 1)
        self.assertGreaterEqual(returned["binary_marker_calls"]["NOALIAS"], 1)

    def test_legacy_httpd_baseline_is_immutable(self):
        specification = (
            Path(__file__).parent / "fixtures" / "httpd_baseline_v1.json"
        )
        report = check_baseline(specification)
        self.assertTrue(report["passed"])
        self.assertTrue(report["statistics_equal"])
        self.assertTrue(all(item["matched"] for item in report["files"]))

    def test_extended_markers_are_explicit_and_comments_are_ignored(self):
        path = (
            Path(__file__).parent
            / "fixtures"
            / "alias_benchmark"
            / "extended_markers.c"
        )
        expectations = parse_alias_expectations(path)
        self.assertEqual(
            [
                (item.marker, item.kind, item.status)
                for item in expectations
            ],
            [
                ("EXPECTEDFAIL_MAYALIAS", "MAYALIAS", "xfail"),
                ("EXPECTEDFAIL_NOALIAS", "NOALIAS", "xfail"),
                ("PARTIALALIAS", "PARTIALALIAS", "required"),
            ],
        )

    def test_suite_process_drains_stdout_and_stderr_while_child_runs(self):
        size = 256 * 1024
        execution = _execute(
            [
                sys.executable,
                "-c",
                (
                    "import sys;"
                    f"sys.stdout.write('o'*{size});sys.stdout.flush();"
                    f"sys.stderr.write('e'*{size});sys.stderr.flush()"
                ),
            ],
            Path(__file__).parent,
            5.0,
        )
        self.assertFalse(execution["timed_out"])
        self.assertEqual(execution["exit_code"], 0)
        self.assertEqual(len(execution["stdout"]), size)
        self.assertEqual(len(execution["stderr"]), size)


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

    def test_incomplete_observation_cannot_match_mayalias(self):
        from scripts.alias_benchmark_analysis import AliasObservation

        observation = AliasObservation(
            "main",
            0x1000,
            "MAYALIAS",
            "MAYALIAS",
            "MAYALIAS",
            12,
            "p",
            "q",
            (),
            ("At least one target is unresolved",),
            False,
            ("ADDRESS_UNRESOLVED",),
        )
        self.assertFalse(observation.matched)

    def test_suite_gate_rejects_incomplete_mayalias(self):
        sample = {
            "markers": {
                "MUSTALIAS": 0,
                "MAYALIAS": 1,
                "NOALIAS": 0,
                "PARTIALALIAS": 0,
                "EXPECTEDFAIL_MAYALIAS": 0,
                "EXPECTEDFAIL_NOALIAS": 0,
            },
            "smoke_only": False,
        }
        execution = {"exit_code": 0, "timed_out": False}
        report = {
            "matched": 0,
            "observations": [{
                "expected": "MAYALIAS",
                "expected_status": "required",
                "predicted": "INCOMPLETE",
                "complete": False,
                "matched": False,
                "reason_codes": ["ADDRESS_UNRESOLVED"],
            }],
            "diagnostics": [],
        }
        outcome = evaluate_sample(sample, execution, report)
        self.assertFalse(outcome["passed"])
        self.assertEqual(outcome["complete_required"], 0)
        self.assertEqual(outcome["reason_codes"], {"ADDRESS_UNRESOLVED": 1})

    def test_smoke_only_sample_has_no_alias_denominator(self):
        sample = {
            "markers": {marker: 0 for marker in (
                "MUSTALIAS",
                "MAYALIAS",
                "NOALIAS",
                "PARTIALALIAS",
                "EXPECTEDFAIL_MAYALIAS",
                "EXPECTEDFAIL_NOALIAS",
            )},
            "smoke_only": True,
        }
        execution = {"exit_code": 0, "timed_out": False}
        report = {"matched": 0, "observations": [], "diagnostics": []}
        outcome = evaluate_sample(sample, execution, report)
        self.assertTrue(outcome["passed"])
        self.assertEqual(outcome["required"], 0)


@unittest.skipUnless(
    SIMPLE_SOURCE.is_file() and SIMPLE_BINARY.is_file(),
    "Test-Suite-master simple_1 fixture is unavailable",
)
class StackAddressIdentityTests(unittest.TestCase):
    def test_distinct_int_addresses_do_not_overlap_at_pointer_width(self):
        report = analyze_alias_benchmark(SIMPLE_SOURCE, SIMPLE_BINARY)
        self.assertEqual(
            [item.predicted for item in report.observations],
            ["NOALIAS", "MUSTALIAS"],
        )
        self.assertTrue(all(item.complete for item in report.observations))
        self.assertTrue(all(item.matched for item in report.observations))


@unittest.skipUnless(
    ARRAY_ONE_SOURCE.is_file() and ARRAY_ONE_BINARY.is_file(),
    "Test-Suite-master array_alias_1 fixture is unavailable",
)
class UninitializedStackPointerTests(unittest.TestCase):
    def test_uninitialized_local_pointer_is_an_empty_points_to_alternative(self):
        report = analyze_alias_benchmark(ARRAY_ONE_SOURCE, ARRAY_ONE_BINARY)
        self.assertEqual(
            [item.predicted for item in report.observations],
            ["NOALIAS", "NOALIAS", "NOALIAS", "MUSTALIAS"],
        )
        self.assertTrue(all(item.complete for item in report.observations))
        self.assertTrue(all(item.matched for item in report.observations))
        self.assertTrue(any(
            "empty points-to" in evidence
            for item in report.observations
            for evidence in item.evidence
        ))


@unittest.skipUnless(
    ARRAY_SIX_SOURCE.is_file() and ARRAY_SIX_BINARY.is_file(),
    "Test-Suite-master array_alias_6 fixture is unavailable",
)
class IndexedStackAddressTests(unittest.TestCase):
    def test_unknown_array_indexes_do_not_become_exact_stack_offsets(self):
        report = analyze_alias_benchmark(ARRAY_SIX_SOURCE, ARRAY_SIX_BINARY)
        self.assertEqual(
            [item.predicted for item in report.observations],
            ["INCOMPLETE", "MUSTALIAS"],
        )
        self.assertFalse(report.observations[0].complete)
        self.assertIn("ADDRESS_UNRESOLVED", report.observations[0].reason_codes)
        self.assertTrue(report.observations[1].matched)


@unittest.skipUnless(
    GLOBAL_ONE_SOURCE.is_file() and GLOBAL_ONE_BINARY.is_file(),
    "Test-Suite-master global_1 fixture is unavailable",
)
class GlobalStoreSummaryTests(unittest.TestCase):
    def test_direct_callee_global_stores_survive_summary_compilation(self):
        report = analyze_alias_benchmark(GLOBAL_ONE_SOURCE, GLOBAL_ONE_BINARY)
        self.assertEqual(
            [item.predicted for item in report.observations],
            ["NOALIAS", "MUSTALIAS"],
        )
        self.assertTrue(all(item.complete for item in report.observations))
        self.assertTrue(all(item.matched for item in report.observations))


@unittest.skipUnless(
    GLOBAL_TWO_SOURCE.is_file() and GLOBAL_TWO_BINARY.is_file(),
    "Test-Suite-master global_2 fixture is unavailable",
)
class GlobalAddressCanonicalizationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.report = analyze_alias_benchmark(
            GLOBAL_TWO_SOURCE, GLOBAL_TWO_BINARY
        )

    def test_constant_relocated_addresses_use_the_containing_segment_root(self):
        observation = self.report.observations[0]
        self.assertEqual(observation.predicted, "NOALIAS")
        self.assertTrue(observation.complete)
        self.assertTrue(observation.matched)

    def test_marker_boundary_preserves_cfg_proved_must_execute_stores(self):
        observation = self.report.observations[1]
        self.assertEqual(observation.predicted, "MUSTALIAS")
        self.assertTrue(observation.complete)
        self.assertTrue(observation.matched)


@unittest.skipUnless(
    GLOBAL_FOUR_SOURCE.is_file() and GLOBAL_FOUR_BINARY.is_file(),
    "Test-Suite-master global_4 fixture is unavailable",
)
class DemandedStoreAddressTests(unittest.TestCase):
    def test_unique_loaded_argument_is_a_precise_store_address(self):
        report = analyze_alias_benchmark(GLOBAL_FOUR_SOURCE, GLOBAL_FOUR_BINARY)
        self.assertEqual(
            [item.predicted for item in report.observations],
            ["NOALIAS", "MUSTALIAS"],
        )
        self.assertTrue(all(item.complete for item in report.observations))
        self.assertTrue(all(item.matched for item in report.observations))


@unittest.skipUnless(
    RETURN_SOURCE.is_file() and RETURN_BINARY.is_file(),
    "Test-Suite-master return fixture is unavailable",
)
class AllocationReturnTests(unittest.TestCase):
    def test_distinct_wrapper_calls_instantiate_distinct_heap_objects(self):
        report = analyze_alias_benchmark(RETURN_SOURCE, RETURN_BINARY)
        self.assertEqual(
            [item.predicted for item in report.observations],
            ["NOALIAS"],
        )
        self.assertTrue(all(item.complete for item in report.observations))
        self.assertTrue(all(item.matched for item in report.observations))


@unittest.skipUnless(
    FUNCTION_POINTER_SOURCE.is_file()
    and FUNCTION_POINTER_BINARY.is_file()
    and FUNCTION_POINTER_TWO_SOURCE.is_file()
    and FUNCTION_POINTER_TWO_BINARY.is_file(),
    "Test-Suite-master function pointer fixtures are unavailable",
)
class IndirectCallerContextTests(unittest.TestCase):
    def test_unique_indirect_target_specializes_marker_formals(self):
        first = analyze_alias_benchmark(
            FUNCTION_POINTER_SOURCE, FUNCTION_POINTER_BINARY
        )
        second = analyze_alias_benchmark(
            FUNCTION_POINTER_TWO_SOURCE, FUNCTION_POINTER_TWO_BINARY
        )
        self.assertEqual(
            [item.predicted for item in first.observations],
            ["MUSTALIAS"],
        )
        self.assertEqual(
            [item.predicted for item in second.observations],
            ["MUSTALIAS", "NOALIAS"],
        )
        self.assertTrue(all(item.complete for item in first.observations))
        self.assertTrue(all(item.complete for item in second.observations))
        self.assertTrue(all(item.matched for item in first.observations))
        self.assertTrue(all(item.matched for item in second.observations))

if __name__ == "__main__":
    unittest.main()
