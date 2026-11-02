"""Opt-in structured logging for isolated BinaryAnalysis diagnostics."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from threading import Event, Thread
import time
from typing import Any
from collections.abc import Iterator


LOGGER_NAME = "emtaint"
_HANDLER_MARKER = "_emtaint_debug_handler"

# Library imports stay silent until the CLI or an embedding application opts
# in.  The handler also prevents logging.lastResort from printing WARNING
# events during unit tests that exercise bounded/incomplete query paths.
logging.getLogger(LOGGER_NAME).addHandler(logging.NullHandler())


class _JsonLineFormatter(logging.Formatter):
    """Serialize one logging record as one searchable JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        row: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "emtaint_event", record.getMessage()),
        }
        row.update(getattr(record, "emtaint_fields", {}))
        if record.exc_info:
            row["exception"] = self.formatException(record.exc_info)
        return json.dumps(row, sort_keys=True, default=str)


class _TextFormatter(logging.Formatter):
    """Render event fields without losing their stable names."""

    def format(self, record: logging.LogRecord) -> str:
        rendered = super().format(record)
        fields = getattr(record, "emtaint_fields", {})
        if fields:
            rendered += " " + json.dumps(fields, sort_keys=True, default=str)
        return rendered


def shutdown_logging() -> None:
    """Remove and close handlers installed by :func:`configure_logging`."""

    logger = logging.getLogger(LOGGER_NAME)
    for handler in tuple(logger.handlers):
        if getattr(handler, _HANDLER_MARKER, False):
            logger.removeHandler(handler)
            handler.close()


def configure_logging(
    level: str = "WARNING",
    path: Path | None = None,
    *,
    json_lines: bool = False,
    console: bool = False,
) -> logging.Logger:
    """Configure the project logger once, creating any log file exclusively.

    The caller must validate the destination boundary.  File mode ``x`` keeps
    diagnostics append-only with respect to historical analysis artifacts.
    """

    numeric_level = logging.getLevelNamesMapping().get(level.upper())
    if not isinstance(numeric_level, int):
        raise ValueError(f"Unknown logging level: {level}")
    shutdown_logging()
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(numeric_level)
    logger.propagate = False
    text_formatter = _TextFormatter(
        "%(asctime)s %(levelname)s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handlers: list[logging.Handler] = []
    if path is not None:
        file_handler = logging.FileHandler(path, mode="x", encoding="utf8")
        file_handler.setFormatter(_JsonLineFormatter() if json_lines else text_formatter)
        handlers.append(file_handler)
    if path is None or console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(text_formatter)
        handlers.append(console_handler)
    for handler in handlers:
        setattr(handler, _HANDLER_MARKER, True)
        handler.setLevel(numeric_level)
        logger.addHandler(handler)
    return logger


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.DEBUG,
    error: BaseException | None = None,
    **fields: object,
) -> None:
    """Emit a named event with small structured diagnostic fields."""

    if not logger.isEnabledFor(level):
        return
    exc_info = None if error is None else (type(error), error, error.__traceback__)
    logger.log(
        level,
        event,
        extra={"emtaint_event": event, "emtaint_fields": fields},
        exc_info=exc_info,
    )


@contextmanager
def progress_heartbeat(
    logger: logging.Logger,
    event: str,
    *,
    interval_seconds: float = 10.0,
    level: int = logging.INFO,
    **fields: object,
) -> Iterator[None]:
    """Emit elapsed-time progress while one opaque analysis call is active."""

    if interval_seconds <= 0:
        raise ValueError("Heartbeat interval must be positive")
    stopped = Event()
    started = time.monotonic()

    def report() -> None:
        while not stopped.wait(interval_seconds):
            log_event(
                logger,
                event,
                level=level,
                elapsed_seconds=time.monotonic() - started,
                **fields,
            )

    thread = Thread(target=report, name="emtaint-log-heartbeat", daemon=True)
    thread.start()
    try:
        yield
    finally:
        stopped.set()
        thread.join(timeout=interval_seconds)
