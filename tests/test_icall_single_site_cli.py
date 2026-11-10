"""CLI contracts for deterministic single-site iCall analysis."""

from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from emtaint.cli import OutputLock, build_parser, prepare_output, validate_arguments, write


class SingleSiteCLIContracts(unittest.TestCase):
    def parse(self, *values: str):
        return build_parser().parse_args(values)

    def test_hexadecimal_and_decimal_sites_are_equivalent(self) -> None:
        hexadecimal = self.parse("-i", "-f", "httpd", "--site", "0x1D688")
        decimal = self.parse("-i", "-f", "httpd", "--site", "120456")
        self.assertEqual(hexadecimal.site, 0x1D688)
        self.assertEqual(decimal.site, hexadecimal.site)
        validate_arguments(hexadecimal)
        validate_arguments(decimal)

    def test_icall_requires_site_but_not_frontend_or_output_paths(self) -> None:
        missing = self.parse("-i", "-f", "httpd")
        with self.assertRaisesRegex(ValueError, "--site"):
            validate_arguments(missing)
        valid = self.parse("-i", "-f", "httpd", "--site", "0x1D688")
        validate_arguments(valid)
        self.assertIsNone(valid.ida_data)
        self.assertIsNone(valid.acquisition)
        self.assertIsNone(valid.output)

    def test_taint_rejects_site(self) -> None:
        args = self.parse(
            "-t", "-f", "httpd", "--site", "0x1D688",
            "--output", "datas/run", "--ida-data", "ida", "--acquisition", "a",
        )
        with self.assertRaisesRegex(ValueError, "-i/alias"):
            validate_arguments(args)

    def test_default_output_is_inside_datas(self) -> None:
        args = self.parse(
            "-i", "-f", "somewhere/httpd", "--site", "0x1D688"
        )
        validate_arguments(args)
        path = prepare_output(args, ROOT)
        self.assertEqual(
            path,
            ROOT / "datas" / "icall" / "httpd" / "0x1d688",
        )

    def test_output_cannot_escape_datas(self) -> None:
        args = self.parse(
            "-i", "-f", "httpd", "--site", "0x1D688",
            "--output", str(ROOT / "outside"),
        )
        validate_arguments(args)
        with self.assertRaisesRegex(ValueError, "escapes"):
            prepare_output(args, ROOT)

    def test_existing_output_and_atomic_replacement(self) -> None:
        folder = ROOT / "datas" / "tests" / uuid.uuid4().hex
        try:
            args = self.parse(
                "-i", "-f", "httpd", "--site", "0x1D688",
                "--output", str(folder),
            )
            first = prepare_output(args, ROOT)
            second = prepare_output(args, ROOT)
            self.assertEqual(first, second)
            artifact = folder / "icall.json"
            write(artifact, {"run": 1})
            write(artifact, {"run": 2})
            self.assertEqual(json.loads(artifact.read_text(encoding="utf8")), {"run": 2})
        finally:
            if folder.exists():
                shutil.rmtree(folder)

    def test_output_lock_rejects_a_concurrent_writer(self) -> None:
        folder = ROOT / "datas" / "tests" / uuid.uuid4().hex
        folder.mkdir(parents=True)
        first = OutputLock(folder, "one")
        second = OutputLock(folder, "two")
        try:
            first.acquire()
            with self.assertRaisesRegex(ValueError, "active lock"):
                second.acquire()
        finally:
            first.release()
            if folder.exists():
                shutil.rmtree(folder)


if __name__ == "__main__":
    unittest.main()
