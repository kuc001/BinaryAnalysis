"""Batch graph refinement with dependency-driven reanalysis and an explicit cap."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
import logging
import time
from typing import Protocol

from emtaint.analysis.controlflow.targets import TargetGraphUpdater
from emtaint.analysis.framework.runtime import AnalysisRuntime
from emtaint.analysis.framework.state import TargetFact
from emtaint.core import FunctionId
from emtaint.core.contracts import Assessment
from emtaint.debugging import log_event
from emtaint.memory.engine import combine, over


LOGGER = logging.getLogger(__name__)


class FunctionAnalysisResult(Protocol):
    """Minimum per-function result consumed by the fixed-point scheduler."""

    targets: tuple[TargetFact, ...]
    assessment: Assessment


@dataclass(frozen=True)
class ProgramSearchResult:
    """Final results and explicit remainder of one bounded graph search."""

    results: tuple[tuple[FunctionId, FunctionAnalysisResult], ...]
    rounds: int
    invocations: int
    pending: tuple[FunctionId, ...]
    assessment: Assessment


class CIRProgramSearch:
    """Reanalyze only functions invalidated by new CFG or CG evidence."""

    def __init__(
        self,
        runtime: AnalysisRuntime,
        updater: TargetGraphUpdater,
        analyze: Callable[[FunctionId], FunctionAnalysisResult],
        max_rounds: int = 3,
        order: Callable[[Iterable[FunctionId]], Iterable[FunctionId]] | None = None,
    ) -> None:
        """Configure a dependency-driven fixed-point search.

        Args:
            runtime: Session-owned graphs, epochs, caches, and pending set.
            updater: Commits target facts into CFG/CG and reports affected users.
            analyze: Callback that builds a fresh scoped analysis for one function.
            max_rounds: Positive hard cap for graph reanalysis rounds.
            order: Optional deterministic ordering, usually callee-first.
        """

        if type(max_rounds) is not int or max_rounds < 1:
            raise ValueError("Positive round budget required")
        self.runtime = runtime
        self.updater = updater
        self.analyze = analyze
        self.max_rounds = max_rounds
        self.order = order

    def run(
        self,
        functions: Mapping[FunctionId, object] | Iterable[FunctionId],
    ) -> ProgramSearchResult:
        """Run until graph facts stabilize or the round cap is exhausted.

        Args:
            functions: Allowed function identities. A mapping contributes its keys.

        Returns:
            Latest result per analyzed function plus an explicit pending frontier.
        """

        started = time.monotonic()
        allowed = frozenset(functions)
        todo = set(allowed)
        results: dict[FunctionId, FunctionAnalysisResult] = {}
        rounds = 0
        invocations = 0
        notes = []
        log_event(
            LOGGER,
            "icall.search.started",
            level=logging.INFO,
            functions=len(allowed),
            max_rounds=self.max_rounds,
        )

        while todo and rounds < self.max_rounds:
            rounds += 1
            self.runtime.pending.difference_update(todo)
            batch: list[TargetFact] = []
            selected = self.order(todo) if self.order else sorted(
                todo,
                key=lambda function: function.rva,
            )
            ordered = tuple(selected)
            log_event(
                LOGGER,
                "icall.search.round.started",
                level=logging.INFO,
                round=rounds,
                worklist=len(ordered),
                functions=[hex(function.rva) for function in ordered],
                pending_before=len(self.runtime.pending),
            )

            for position, function in enumerate(ordered, 1):
                # The callback constructs a fresh port scoped to the current
                # graph revision; stale scoped objects are never reused.
                log_event(
                    LOGGER,
                    "icall.search.function.dispatched",
                    function=hex(function.rva),
                    round=rounds,
                    position=position,
                    total=len(ordered),
                )
                result = self.analyze(function)
                results[function] = result
                batch.extend(result.targets)
                invocations += 1

            event_start = len(self.runtime.events)
            affected = self.updater.apply(batch)
            todo = set(self.runtime.pending) & allowed
            log_event(
                LOGGER,
                "icall.search.round.completed",
                level=logging.INFO,
                round=rounds,
                target_facts=len(batch),
                target_values=sum(len(fact.targets) for fact in batch),
                affected=len(affected),
                next_worklist=len(todo),
                new_runtime_events=self.runtime.events[event_start:],
                total_invocations=invocations,
            )

        if todo:
            notes.append(
                over(
                    "Graph reanalysis round budget exhausted; pending callers retained",
                    True,
                )
            )
        notes.extend(result.assessment for result in results.values())
        log_event(
            LOGGER,
            "icall.search.completed",
            level=logging.INFO,
            rounds=rounds,
            invocations=invocations,
            pending=len(self.runtime.pending),
            results=len(results),
            exhausted=bool(todo),
            wall_seconds=time.monotonic() - started,
        )
        return ProgramSearchResult(
            tuple(sorted(results.items(), key=lambda pair: pair[0].rva)),
            rounds,
            invocations,
            tuple(sorted(self.runtime.pending, key=lambda function: function.rva)),
            combine(notes),
        )
