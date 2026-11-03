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

from emtaint.debugging import (
    EventSampler,
    configure_logging,
    function_address_fields,
    log_event,
    progress_heartbeat,
    shutdown_logging,
)


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

    @staticmethod
    def _rows(path: Path) -> list[dict[str, object]]:
        """Read the formatted JSON array written by the diagnostic handler."""

        return json.loads(path.read_text(encoding="utf8"))

    def test_jsonl_event_contains_named_context(self) -> None:
        path = self.folder / "events.jsonl"
        logger = configure_logging("DEBUG", path, json_lines=True)
        log_event(logger.getChild("test"), "query.completed", query_id="q1", steps=7)
        shutdown_logging()
        rows = self._rows(path)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row["event"], "query.completed")
        self.assertEqual(row["query_id"], "q1")
        self.assertEqual(row["steps"], 7)
        self.assertEqual(row["source_file"], "test_debug_logging.py")
        self.assertGreater(row["source_line"], 0)
        self.assertEqual(row["source_function"], "test_jsonl_event_contains_named_context")

    def test_function_address_fields_keep_rva_and_ida_va_explicit(self) -> None:
        path = self.folder / "addresses.jsonl"
        logger = configure_logging("DEBUG", path, json_lines=True)
        log_event(
            logger.getChild("orchestration.program_search"),
            "icall.search.function.dispatched",
            **function_address_fields(0x8EE0, 0x8000),
        )
        shutdown_logging()
        row = self._rows(path)[0]
        self.assertEqual(row["function"], "0x8ee0")
        self.assertEqual(row["function_rva"], "0x8ee0")
        self.assertEqual(row["function_va"], "0x10ee0")
        va_fields = function_address_fields(0x8EE0, 0x8000, legacy_field="va")
        self.assertEqual(va_fields["function"], "0x10ee0")

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
        rows = self._rows(path)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["event"], "visible")

    def test_file_and_live_console_use_independent_formats(self) -> None:
        path = self.folder / "events.jsonl"
        console = io.StringIO()
        with redirect_stderr(console):
            logger = configure_logging("INFO", path, json_lines=True, console=True)
            log_event(logger.getChild("icall"), "icall.search.started", level=logging.INFO, functions=23)
            shutdown_logging()
        self.assertEqual(self._rows(path)[0]["functions"], 23)
        self.assertIn("icall.search.started", console.getvalue())
        self.assertIn('"functions": 23', console.getvalue())
        self.assertIn("test_debug_logging.py:", console.getvalue())
        self.assertIn("test_file_and_live_console_use_independent_formats", console.getvalue())

    def test_console_level_can_hide_debug_while_file_retains_it(self) -> None:
        path = self.folder / "events.jsonl"
        console = io.StringIO()
        with redirect_stderr(console):
            logger = configure_logging(
                "DEBUG",
                path,
                json_lines=True,
                console=True,
                console_level="INFO",
            )
            log_event(logger, "debug.detail", value=1)
            log_event(logger, "stage.completed", level=logging.INFO, value=2)
            shutdown_logging()
        rows = self._rows(path)
        self.assertEqual([row["event"] for row in rows], ["debug.detail", "stage.completed"])
        self.assertNotIn("debug.detail", console.getvalue())
        self.assertIn("stage.completed", console.getvalue())

    def test_heartbeat_reports_an_opaque_long_running_stage(self) -> None:
        path = self.folder / "heartbeat.jsonl"
        logger = configure_logging("INFO", path, json_lines=True)
        with progress_heartbeat(logger, "icall.analysis.heartbeat", interval_seconds=0.01, function="0x1f9a0"):
            deadline = time.monotonic() + 0.5
            while time.monotonic() < deadline:
                if path.exists():
                    try:
                        if len(self._rows(path)) >= 2:
                            break
                    except json.JSONDecodeError:
                        pass
                time.sleep(0.01)
        shutdown_logging()
        rows = self._rows(path)
        self.assertGreaterEqual(len(rows), 2)
        self.assertTrue(all(row["function"] == "0x1f9a0" for row in rows))
        self.assertTrue(all(row["elapsed_seconds"] > 0 for row in rows))
        self.assertTrue(all(row["source_file"] == "test_debug_logging.py" for row in rows))
        self.assertTrue(
            all(row["source_function"] == "test_heartbeat_reports_an_opaque_long_running_stage" for row in rows)
        )

    def test_sampler_bounds_high_frequency_events_and_keeps_callsite(self) -> None:
        path = self.folder / "sampled.jsonl"
        logger = configure_logging("DEBUG", path, json_lines=True)
        sampler = EventSampler(logger, first=2, every=3)
        for value in range(7):
            sampler.emit("sse.node", value=value)
        shutdown_logging()
        rows = self._rows(path)
        self.assertEqual(
            [row["event_sequence"] for row in rows],
            [1, 2, 3, 6],
        )
        self.assertEqual(sampler.counts(), {"sse.node": 7})
        self.assertTrue(
            all(row["source_file"] == "test_debug_logging.py" for row in rows)
        )

    def test_json_file_is_indented_and_valid_while_logging(self) -> None:
        path = self.folder / "readable.jsonl"
        logger = configure_logging("DEBUG", path, json_lines=True)
        log_event(logger, "first", value=1)
        self.assertEqual([row["event"] for row in self._rows(path)], ["first"])
        log_event(logger, "second", value=2)
        self.assertEqual(
            [row["event"] for row in self._rows(path)],
            ["first", "second"],
        )
        shutdown_logging()
        content = path.read_text(encoding="utf8")
        self.assertIn('\n    "event": "first",\n', content)
        self.assertTrue(content.startswith("[\n  {"))
        self.assertTrue(content.endswith("\n]\n"))


if __name__ == "__main__":
    unittest.main()
