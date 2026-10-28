import copy
from pathlib import Path
import sys
import tempfile
import unittest

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
sys.path.insert(0, str(SCRIPTS))
from compare_baseline import compare_icalls, compare_results, normalize_results
from legacy_baseline import inventory, legacy_import_write_risks, require_isolation, validate_run_root, write_json
from legacy_readonly_bootstrap import (ForbiddenMutation, WriteGuard, explicit_ply_arguments,
                                      ply_options)


class ComparatorTests(unittest.TestCase):
    def fixture(self):
        return {"icall": {"time": "1", "recovered_icall": 1},
                "taint_1": {"buffer_overflow": {"abc": {
                    "offset": [12, 8], "info": [2, 1, 3, 0], "func": 100,
                    "name": "strcpy", "path": [10, 20]}}}}

    def test_equal(self):
        self.assertTrue(compare_results(self.fixture(), self.fixture())["semantic_equal"])

    def test_timing_is_reported(self):
        after = self.fixture()
        after["icall"]["time"] = "2"
        report = compare_results(self.fixture(), after)
        self.assertTrue(report["semantic_equal"])
        self.assertEqual(len(report["timing_changes"]), 1)

    def test_offsets_only_may_reorder(self):
        after = self.fixture()
        after["taint_1"]["buffer_overflow"]["abc"]["offset"].reverse()
        report = compare_results(self.fixture(), after)
        self.assertTrue(report["semantic_equal"])
        self.assertEqual(len(report["order_only_changes"]), 1)

    def test_info_order_is_evidence(self):
        after = self.fixture()
        after["taint_1"]["buffer_overflow"]["abc"]["info"].reverse()
        self.assertFalse(compare_results(self.fixture(), after)["semantic_equal"])

    def test_path_order_is_evidence(self):
        after = self.fixture()
        after["taint_1"]["buffer_overflow"]["abc"]["path"].reverse()
        self.assertFalse(compare_results(self.fixture(), after)["semantic_equal"])

    def test_types_inside_evidence_lists_are_preserved(self):
        self.assertFalse(compare_results({"info": [1]}, {"info": [True]})["semantic_equal"])
        self.assertFalse(compare_results({"path": [{"x": 1}]},
                                         {"path": [{"x": 1.0}]})["semantic_equal"])

    def test_missing_finding(self):
        after = self.fixture()
        after["taint_1"]["buffer_overflow"].clear()
        self.assertFalse(compare_results(self.fixture(), after)["semantic_equal"])

    def test_missing_and_null_differ(self):
        self.assertFalse(compare_results({"evidence": None}, {})["semantic_equal"])

    def test_numeric_types_not_coerced(self):
        self.assertFalse(compare_results({"x": 1}, {"x": True})["semantic_equal"])

    def test_offset_duplicates_not_removed(self):
        after = self.fixture()
        after["taint_1"]["buffer_overflow"]["abc"]["offset"].append(8)
        self.assertFalse(compare_results(self.fixture(), after)["semantic_equal"])

    def test_normalization_keeps_original(self):
        original = self.fixture()
        saved = copy.deepcopy(original)
        normalized = normalize_results(original)
        self.assertEqual(original, saved)
        self.assertEqual(normalized["taint_1"]["buffer_overflow"]["abc"]["offset"], [8, 12])
        self.assertEqual(normalized["taint_1"]["buffer_overflow"]["abc"]["info"], [2, 1, 3, 0])

    def test_icall_set_order(self):
        report = compare_icalls({"100": {"120": [3, 2, "puts"]}},
                                {"100": {"120": ["puts", 2, 3]}})
        self.assertTrue(report["semantic_equal"])
        self.assertTrue(report["target_order_only"])

    def test_icall_target_loss(self):
        self.assertFalse(compare_icalls({"100": {"120": [2, 3]}},
                                       {"100": {"120": [2]}})["semantic_equal"])

    def test_icall_moved_callsite(self):
        self.assertFalse(compare_icalls({"100": {"120": [2]}},
                                       {"100": {"124": [2]}})["semantic_equal"])

    def test_icall_duplicates_rejected(self):
        with self.assertRaises(ValueError):
            compare_icalls({"100": {"120": [2, 2]}}, {})

    def test_icall_hex_key_rejected(self):
        with self.assertRaises(ValueError):
            compare_icalls({"0x100": {}}, {})

    def test_icall_bool_target_rejected(self):
        with self.assertRaises(ValueError):
            compare_icalls({"100": {"120": [True]}}, {})

    def test_run_root_cannot_be_legacy_or_target(self):
        with self.assertRaises(RuntimeError):
            validate_run_root(SCRIPTS.parent.parent / "EmTaint")
        with self.assertRaises(RuntimeError):
            validate_run_root(SCRIPTS.parent)

    def test_local_angr_import_write_risk_is_detected_without_import(self):
        risks = legacy_import_write_risks()
        self.assertTrue(risks)
        self.assertTrue(any(risk["line"] == 1616 for risk in risks))

    def test_execution_requires_validated_matching_bootstrap(self):
        for proof in (None, {}, {"verified": False}, {"verified": True, "bootstrap_sha256": "wrong"}):
            with self.assertRaisesRegex(RuntimeError, "isolation proof is required"):
                require_isolation(proof)

    def test_isolation_preserves_grammar_start_and_optimization(self):
        source = {"module": object(), "start": "parameter_declaration", "optimize": False,
                  "debug": False}
        isolated = ply_options(source, Path("isolated-cache"), "disabled")
        for key in source:
            self.assertEqual(source[key], isolated[key])
        self.assertFalse(isolated["write_tables"])
        self.assertNotIn("write_tables", source)
        reference = ply_options(source, Path("isolated-cache"), "redirect")
        self.assertNotIn("write_tables", reference)

    def test_explicit_positional_lex_module_is_preserved(self):
        def lex(module=None, object=None, outputdir=None):
            pass
        module = object()
        self.assertIs(explicit_ply_arguments(lex, (module,), {}, lexer=True)["module"], module)
        with self.assertRaisesRegex(RuntimeError, "implicit"):
            explicit_ply_arguments(lex, (), {}, lexer=True)

    def test_full_inventory_detects_same_content_timestamp_change(self):
        import os
        with tempfile.TemporaryDirectory(dir=SCRIPTS.parent) as temp:
            root = Path(temp).resolve()
            self.assertTrue(root.is_relative_to(SCRIPTS.parent))
            path = root / "parser-table.py"
            path.write_text("same content")
            before = inventory(root)
            os.utime(path, ns=(path.stat().st_atime_ns, path.stat().st_mtime_ns + 1_000_000_000))
            after = inventory(root)
            self.assertEqual(before[0]["sha256"], after[0]["sha256"])
            self.assertNotEqual(before, after)

    def test_guard_blocks_writes_and_metadata_outside_allowed_roots(self):
        import os
        with tempfile.TemporaryDirectory(dir=SCRIPTS.parent) as temp:
            root = Path(temp).resolve()
            self.assertTrue(root.is_relative_to(SCRIPTS.parent))
            allowed = root / "allowed"
            allowed.mkdir()
            outside = root / "outside.txt"
            outside.write_text("unchanged")
            before = outside.stat().st_mtime_ns
            guard = WriteGuard([allowed]).install()
            try:
                (allowed / "ok.txt").write_text("ok")
                with self.assertRaises(ForbiddenMutation):
                    outside.write_text("bad")
                with self.assertRaises(ForbiddenMutation):
                    os.utime(outside, None)
                with self.assertRaises(ForbiddenMutation):
                    os.open(str(outside), os.O_WRONLY | os.O_TRUNC)
                self.assertEqual(outside.read_text(), "unchanged")
                self.assertEqual(outside.stat().st_mtime_ns, before)
                self.assertEqual(len(guard.violations), 3)
            finally:
                guard.restore()

    def test_artifacts_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory(dir=SCRIPTS.parent) as temp:
            path = Path(temp) / "manifest.json"
            self.assertTrue(path.resolve().is_relative_to(SCRIPTS.parent))
            write_json(path, {"value": 1})
            with self.assertRaises(FileExistsError):
                write_json(path, {"value": 2})


if __name__ == "__main__":
    unittest.main()
