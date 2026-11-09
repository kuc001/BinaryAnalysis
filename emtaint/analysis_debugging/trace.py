"""Optional bounded structural trace for analysis-rule decisions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path
from threading import Lock
from typing import Iterable


def trace_identity(value: object) -> str:
    """Return a compact existing identity without creating analysis state."""

    if isinstance(value, str):
        return value
    identifier = getattr(value, "id", None)
    if isinstance(identifier, str):
        return identifier
    key = getattr(value, "key", None)
    if isinstance(key, str):
        return key
    if identifier is not None:
        identifier_key = getattr(identifier, "key", None)
        if isinstance(identifier_key, str):
            return identifier_key
    return type(value).__name__


@dataclass(frozen=True, slots=True)
class AnalysisTraceEvent:
    """One rule application connecting existing analysis inputs and outputs."""

    sequence: int
    rule: str
    function_rva: int
    input_ids: tuple[str, ...]
    output_ids: tuple[str, ...]
    origin_id: str | None = None
    instruction_rva: int | None = None
    reason: str | None = None


class AnalysisTraceRecorder:
    """Thread-safe opt-in recorder with a hard event bound and filters."""

    def __init__(
        self,
        *,
        enabled: bool = False,
        max_events: int = 10_000,
        rules: Iterable[str] | None = None,
        identities: Iterable[str] | None = None,
    ) -> None:
        if max_events < 1:
            raise ValueError("Trace max_events must be positive")
        self.enabled = enabled
        self.max_events = max_events
        self.rules = frozenset(rules or ())
        self.identities = frozenset(identities or ())
        self._events: list[AnalysisTraceEvent] = []
        self._dropped = 0
        self._lock = Lock()

    @property
    def dropped(self) -> int:
        """Return the number of matching events omitted by the hard bound."""

        return self._dropped

    def record(
        self,
        rule: str,
        function_rva: int,
        *,
        inputs: Iterable[object] = (),
        outputs: Iterable[object] = (),
        origin_id: str | None = None,
        instruction_rva: int | None = None,
        reason: str | None = None,
    ) -> None:
        """Append one event without invoking an analysis operation."""

        if not self.enabled or (self.rules and rule not in self.rules):
            return
        input_ids = tuple(trace_identity(value) for value in inputs)
        output_ids = tuple(trace_identity(value) for value in outputs)
        if self.identities and not self.identities.intersection(
            (*input_ids, *output_ids)
        ):
            return
        with self._lock:
            if len(self._events) >= self.max_events:
                self._dropped += 1
                return
            self._events.append(
                AnalysisTraceEvent(
                    len(self._events) + 1,
                    rule,
                    function_rva,
                    input_ids,
                    output_ids,
                    origin_id,
                    instruction_rva,
                    reason,
                )
            )

    def events(self) -> tuple[AnalysisTraceEvent, ...]:
        """Return an immutable snapshot in sequence order."""

        with self._lock:
            return tuple(self._events)

    def events_for(self, identity: object) -> tuple[AnalysisTraceEvent, ...]:
        """Return events that consume or produce an existing identity."""

        key = trace_identity(identity)
        return tuple(
            event
            for event in self.events()
            if key in event.input_ids or key in event.output_ids
        )

    def export_jsonl(self, path: str | Path) -> None:
        """Exclusively create a JSONL trace sidecar from the current snapshot."""

        destination = Path(path)
        with destination.open("x", encoding="utf8", newline="\n") as stream:
            for event in self.events():
                stream.write(json.dumps(asdict(event), sort_keys=True) + "\n")
