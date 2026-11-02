"""Tests for the repository-local, dependency-free quality audit."""

from pathlib import Path
import tempfile
import unittest

from scripts.quality_audit import SAFETY_CODES, _exit_code, audit


class QualityAuditTests(unittest.TestCase):
    """Exercise safety findings, annotations, imports, and SCC detection."""

    def _fixture(self, root: Path) -> Path:
        """Create a two-module package with deliberate, isolated violations."""

        package = root / "fixturepkg"
        package.mkdir()
        (package / "__init__.py").write_text('"""Fixture package."""\n', encoding="utf-8")
        (package / "first.py").write_text(
            "from fixturepkg.second import value\n"
            "from fixturepkg.second import *\n"
            "\n"
            "def public(value):\n"
            "    def nested_helper():\n"
            "        return value\n"
            "    try:\n"
            "        return value\n"
            "    except:\n"
            "        pass\n",
            encoding="utf-8",
        )
        (package / "second.py").write_text(
            '"""Second fixture module."""\n'
            "from fixturepkg import first\n"
            "value = 1\n",
            encoding="utf-8",
        )
        return package

    def test_reports_safety_quality_and_cycle_without_importing(self) -> None:
        """The audit preserves separate safety/debt codes and finds the SCC."""

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            package = self._fixture(Path(folder))
            report = audit(package)

        codes = {finding.code for finding in report.findings}
        self.assertTrue(SAFETY_CODES.intersection(codes))
        self.assertIn("missing-module-doc", codes)
        self.assertIn("missing-callable-doc", codes)
        self.assertIn("missing-callable-type", codes)
        self.assertEqual(report.counts()["missing-callable-doc"], 1)
        self.assertEqual(
            report.cycles,
            (("fixturepkg.first", "fixturepkg.second"),),
        )
        self.assertEqual(_exit_code(report, "none"), 0)
        self.assertEqual(_exit_code(report, "safety"), 1)
        self.assertEqual(_exit_code(report, "all"), 1)

    def test_selected_path_limits_findings_but_keeps_dependency_model(self) -> None:
        """A batch audit reports one file while resolving the complete package."""

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            package = self._fixture(Path(folder))
            selected = package / "second.py"
            report = audit(package, (selected,))

        self.assertEqual(report.findings, ())
        self.assertEqual(report.modules, 3)
        self.assertEqual(len(report.cycles), 1)

    def test_rejects_paths_outside_the_source_root(self) -> None:
        """Caller mistakes fail explicitly instead of producing partial audits."""

        with tempfile.TemporaryDirectory(dir=Path.cwd()) as folder:
            root = Path(folder)
            package = self._fixture(root)
            outside = root / "outside.py"
            outside.write_text("value = 1\n", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "not Python files below"):
                audit(package, (outside,))


if __name__ == "__main__":
    unittest.main()
