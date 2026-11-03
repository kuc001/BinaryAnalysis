"""Opt-in structured logging for isolated BinaryAnalysis diagnostics."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
import inspect
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


def function_address_fields(
    function_rva: int,
    image_base: int,
    *,
    legacy_field: str = "rva",
) -> dict[str, str]:
    """Build unambiguous RVA/VA fields for one function log event.

    Args:
        function_rva: Function address relative to the loaded image base.
        image_base: Absolute image load base used by IDA and the loader.
        legacy_field: Whether the compatibility ``function`` field retains its
            historical ``rva`` or ``va`` value.

    Returns:
        Hexadecimal ``function``, ``function_rva`` and ``function_va`` fields.
    """

    if type(function_rva) is not int or function_rva < 0:
        raise ValueError("Function RVA must be a non-negative integer")
    if type(image_base) is not int or image_base < 0:
        raise ValueError("Image base must be a non-negative integer")
    if legacy_field not in ("rva", "va"):
        raise ValueError("Legacy function field must be rva or va")
    function_va = image_base + function_rva
    return {
        "function": hex(function_rva if legacy_field == "rva" else function_va),
        "function_rva": hex(function_rva),
        "function_va": hex(function_va),
    }


def _source_name(record: logging.LogRecord) -> str:
    """Return only the source basename selected for a logging record."""

    source = getattr(record, "emtaint_source_file", record.pathname)
    return Path(source).name


class _JsonFormatter(logging.Formatter):
    """Serialize one logging record as one readable JSON object."""

    def format(self, record: logging.LogRecord) -> str:
        """Return one stable JSON object containing source and event fields."""

        row: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(
                record.created, timezone.utc
            ).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": getattr(record, "emtaint_event", record.getMessage()),
            "source_file": _source_name(record),
            "source_line": getattr(record, "emtaint_source_line", record.lineno),
            "source_function": getattr(
                record,
                "emtaint_source_function",
                record.funcName,
            ),
        }
        row.update(getattr(record, "emtaint_fields", {}))
        if record.exc_info:
            row["exception"] = self.formatException(record.exc_info)
        return json.dumps(
            row,
            indent=2,
            sort_keys=True,
            ensure_ascii=False,
            default=str,
        )


class _PrettyJsonArrayHandler(logging.FileHandler):
    """Maintain an indented, valid JSON array after every emitted record."""

    def __init__(self, path: Path) -> None:
        self._has_records = False
        super().__init__(path, mode="x", encoding="utf8")
        self.stream.write("[\n]\n")
        self.flush()

    def _open(self):
        """Open with stable LF endings so the closing array can be replaced."""

        return open(
            self.baseFilename,
            self.mode,
            encoding=self.encoding,
            errors=self.errors,
            newline="\n",
        )

    def emit(self, record: logging.LogRecord) -> None:
        """Insert one formatted object before the array's closing bracket."""

        try:
            message = "\n".join(
                "  " + line
                for line in self.format(record).splitlines()
            )
            self.stream.seek(0, 2)
            end = self.stream.tell()
            self.stream.seek(end - 2)
            if self._has_records:
                self.stream.write(",\n")
            self.stream.write(message)
            self.stream.write("\n]\n")
            self.stream.truncate()
            self.flush()
            self._has_records = True
        except Exception:
            self.handleError(record)


class _TextFormatter(logging.Formatter):
    """Render event fields without losing their stable names."""

    def format(self, record: logging.LogRecord) -> str:
        """Return a source-qualified human-readable event line."""

        timestamp = self.formatTime(record, "%Y-%m-%dT%H:%M:%S")
        source_file = _source_name(record)
        source_line = getattr(record, "emtaint_source_line", record.lineno)
        source_function = getattr(
            record,
            "emtaint_source_function",
            record.funcName,
        )
        rendered = (
            f"{timestamp} {record.levelname} {record.name} "
            f"[{source_file}:{source_line} {source_function}] {record.getMessage()}"
        )
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
    console_level: str | None = None,
) -> logging.Logger:
    """Configure the project logger once, creating any log file exclusively.

    The caller must validate the destination boundary.  File mode ``x`` keeps
    diagnostics append-only with respect to historical analysis artifacts.
    """

    numeric_level = getattr(logging, level.upper(), None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Unknown logging level: {level}")
    console_numeric_level = numeric_level
    if console_level is not None:
        console_numeric_level = getattr(logging, console_level.upper(), None)
        if not isinstance(console_numeric_level, int):
            raise ValueError(f"Unknown console logging level: {console_level}")
    shutdown_logging()
    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(min(numeric_level, console_numeric_level))
    logger.propagate = False
    text_formatter = _TextFormatter()
    handlers: list[logging.Handler] = []
    if path is not None:
        file_handler = (
            _PrettyJsonArrayHandler(path)
            if json_lines
            else logging.FileHandler(path, mode="x", encoding="utf8")
        )
        file_handler.setFormatter(_JsonFormatter() if json_lines else text_formatter)
        file_handler.setLevel(numeric_level)
        handlers.append(file_handler)
    if path is None or console:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(text_formatter)
        console_handler.setLevel(console_numeric_level)
        handlers.append(console_handler)
    for handler in handlers:
        setattr(handler, _HANDLER_MARKER, True)
        logger.addHandler(handler)
    return logger


def log_event(
    logger: logging.Logger,
    event: str,
    *,
    level: int = logging.DEBUG,
    error: BaseException | None = None,
    stacklevel: int = 2,
    source_location: tuple[str, int, str] | None = None,
    **fields: object,
) -> None:
    """Emit a named event with small structured diagnostic fields.

    ``stacklevel`` identifies the application call site for both text and JSON
    logs.  Wrapper helpers must add one level so users see the analysis code,
    not the logging utility.
    """

    if not logger.isEnabledFor(level):
        return
    exc_info = None if error is None else (type(error), error, error.__traceback__)
    extra = {"emtaint_event": event, "emtaint_fields": fields}
    if source_location is not None:
        extra.update(
            emtaint_source_file=source_location[0],
            emtaint_source_line=source_location[1],
            emtaint_source_function=source_location[2],
        )
    logger.log(
        level,
        event,
        extra=extra,
        exc_info=exc_info,
        stacklevel=stacklevel,
    )


class EventSampler:
    """Bound high-frequency diagnostics while preserving execution shape.

    The first ``first`` occurrences of each event are logged, followed by one
    event every ``every`` occurrences.  The total occurrence number is stored
    in ``event_sequence`` so a debugger can distinguish a quiet stage from a
    sampled stage without producing multi-gigabyte logs.

    Args:
        logger: Component logger that owns the sampled events.
        first: Number of leading occurrences emitted for every event name.
        every: Sampling interval after the leading occurrences.
    """

    def __init__(
        self,
        logger: logging.Logger,
        *,
        first: int = 20,
        every: int = 1_000,
    ) -> None:
        if first < 0 or every <= 0:
            raise ValueError("Event sampling bounds must be non-negative/positive")
        self._logger = logger
        self._first = first
        self._every = every
        self._counts: dict[str, int] = {}

    def emit(
        self,
        event: str,
        *,
        level: int = logging.DEBUG,
        **fields: object,
    ) -> None:
        """Record one occurrence and emit it when the sampling policy selects it."""

        sequence = self._counts.get(event, 0) + 1
        self._counts[event] = sequence
        if sequence <= self._first or sequence % self._every == 0:
            log_event(
                self._logger,
                event,
                level=level,
                stacklevel=3,
                event_sequence=sequence,
                **fields,
            )

    def counts(self) -> dict[str, int]:
        """Return a detached event-to-occurrence snapshot for final metrics."""

        return dict(self._counts)


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
    source_location = None
    for frame in inspect.stack()[1:]:
        if frame.filename == __file__ or frame.filename.endswith("contextlib.py"):
            continue
        source_location = (frame.filename, frame.lineno, frame.function)
        break
    if source_location is None:
        source_location = (__file__, 0, "progress_heartbeat")

    def report() -> None:
        while not stopped.wait(interval_seconds):
            log_event(
                logger,
                event,
                level=level,
                source_location=source_location,
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
