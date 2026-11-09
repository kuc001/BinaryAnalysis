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
    event_id: str
    rule: str
    function_rva: int
    input_ids: tuple[str, ...]
    output_ids: tuple[str, ...]
    origin_id: str | None = None
    instruction_rva: int | None = None
    reason: str | None = None
    parent_event_id: str | None = None
    parent_event_ids: tuple[str, ...] = ()
    details: tuple[tuple[str, str], ...] = ()


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
        self._last_producer: dict[str, str] = {}
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
        parent_event_id: str | None = None,
        details: Iterable[tuple[str, str]] = (),
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
            parent_ids = tuple(dict.fromkeys(
                self._last_producer[value]
                for value in input_ids
                if value in self._last_producer
            ))
            if parent_event_id is not None and parent_event_id not in parent_ids:
                parent_ids = (parent_event_id, *parent_ids)
            event = AnalysisTraceEvent(
                    len(self._events) + 1,
                    "trace-" + str(len(self._events) + 1),
                    rule,
                    function_rva,
                    input_ids,
                    output_ids,
                    origin_id,
                    instruction_rva,
                    reason,
                    parent_event_id or (parent_ids[-1] if parent_ids else None),
                    parent_ids,
                    tuple(details),
                )
            self._events.append(event)
            for output in output_ids:
                self._last_producer[output] = event.event_id

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

    def causal_slice(self, identity: object, *, max_events: int = 512) -> tuple[AnalysisTraceEvent, ...]:
        """Return the bounded backward dependency slice for an existing identity."""

        if max_events < 1:
            raise ValueError("max_events must be positive")
        events = self.events()
        pending = [trace_identity(identity)]
        seen_values = set()
        selected = {}
        producers = {}
        for event in events:
            for output in event.output_ids:
                producers.setdefault(output, []).append(event)
        while pending and len(selected) < max_events:
            current = pending.pop()
            if current in seen_values:
                continue
            seen_values.add(current)
            for event in reversed(producers.get(current, ())):
                if event.sequence in selected:
                    continue
                selected[event.sequence] = event
                pending.extend(item for item in event.input_ids if item not in seen_values)
        return tuple(selected[key] for key in sorted(selected))

    def export_jsonl(self, path: str | Path) -> None:
        """Exclusively create a JSONL trace sidecar from the current snapshot."""

        destination = Path(path)
        with destination.open("x", encoding="utf8", newline="\n") as stream:
            for event in self.events():
                stream.write(json.dumps(asdict(event), sort_keys=True) + "\n")
