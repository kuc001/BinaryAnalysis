"""Regression tests for opt-in append-only diagnostic logging."""

import json
import logging
from pathlib import Path
import io
from contextlib import redirect_stderr
import time
import sys
import unittest
import uuid


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from emtaint.debugging import configure_logging, log_event, progress_heartbeat, shutdown_logging


class DebugLoggingTests(unittest.TestCase):
    """Keep diagnostics structured, filtered, and non-destructive."""

    def setUp(self) -> None:
        self.folder = ROOT / ".p7-work" / ("test-debug-log-" + uuid.uuid4().hex)
        self.folder.mkdir(parents=True)

    def tearDown(self) -> None:
        shutdown_logging()
        for path in self.folder.iterdir():
            path.unlink()
        self.folder.rmdir()

    def test_jsonl_event_contains_named_context(self) -> None:
        path = self.folder / "events.jsonl"
        logger = configure_logging("DEBUG", path, json_lines=True)
        log_event(logger.getChild("test"), "query.completed", query_id="q1", steps=7)
        shutdown_logging()
        row = json.loads(path.read_text(encoding="utf8"))
        self.assertEqual(row["event"], "query.completed")
        self.assertEqual(row["query_id"], "q1")
        self.assertEqual(row["steps"], 7)

    def test_existing_log_is_never_overwritten(self) -> None:
        path = self.folder / "existing.log"
        path.write_text("keep", encoding="utf8")
        with self.assertRaises(FileExistsError):
            configure_logging("INFO", path)
        self.assertEqual(path.read_text(encoding="utf8"), "keep")

    def test_level_filters_debug_events(self) -> None:
        path = self.folder / "warning.jsonl"
        logger = configure_logging("WARNING", path, json_lines=True)
        log_event(logger, "hidden", value=1)
        log_event(logger, "visible", level=logging.WARNING, value=2)
        shutdown_logging()
        rows = path.read_text(encoding="utf8").splitlines()
        self.assertEqual(len(rows), 1)
        self.assertEqual(json.loads(rows[0])["event"], "visible")

    def test_file_and_live_console_use_independent_formats(self) -> None:
        path = self.folder / "events.jsonl"
        console = io.StringIO()
        with redirect_stderr(console):
            logger = configure_logging("INFO", path, json_lines=True, console=True)
            log_event(logger.getChild("icall"), "icall.search.started", level=logging.INFO, functions=23)
            shutdown_logging()
        self.assertEqual(json.loads(path.read_text(encoding="utf8"))["functions"], 23)
        self.assertIn("icall.search.started", console.getvalue())
        self.assertIn('"functions": 23', console.getvalue())

    def test_heartbeat_reports_an_opaque_long_running_stage(self) -> None:
        path = self.folder / "heartbeat.jsonl"
        logger = configure_logging("INFO", path, json_lines=True)
        with progress_heartbeat(logger, "icall.analysis.heartbeat", interval_seconds=0.01, function="0x1f9a0"):
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                if path.exists() and len(path.read_text(encoding="utf8").splitlines()) >= 2:
                    break
                time.sleep(0.01)
        shutdown_logging()
        rows = [json.loads(line) for line in path.read_text(encoding="utf8").splitlines()]
        self.assertGreaterEqual(len(rows), 2)
        self.assertTrue(all(row["function"] == "0x1f9a0" for row in rows))
        self.assertTrue(all(row["elapsed_seconds"] > 0 for row in rows))


if __name__ == "__main__":
    unittest.main()
