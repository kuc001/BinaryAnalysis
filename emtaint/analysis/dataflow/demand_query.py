"""Explicit result contract for one demand query.

Legacy callers still use tuple-valued ``value`` methods.  New callers can use
this contract to distinguish a completed value set from an incomplete budget
or recurrence frontier without interpreting an empty tuple as proof.
"""

from dataclasses import dataclass
from enum import Enum
import time


class DemandCompleteness(str, Enum):
    """Whether all frontiers of one demand query were resolved."""

    COMPLETE = "complete"
    INCOMPLETE = "incomplete"


@dataclass(frozen=True)
class DemandQueryCost:
    """Resource delta attributable to one top-level demand query."""

    scalar_steps: int
    memory_work: int
    wall_seconds: float


@dataclass(frozen=True)
class DemandQueryResult:
    """Values and evidence state returned by one demand query."""

    values: tuple
    completeness: DemandCompleteness
    diagnostics: tuple[str, ...]
    cost: DemandQueryCost


class DemandQueryRunner:
    """Run top-level queries without leaking recurrence placeholders."""

    def __init__(self, owner, incomplete_errors: tuple[type[BaseException], ...]):
        self.owner = owner
        self.incomplete_errors = incomplete_errors
        self.completed = 0
        self.incomplete = 0
        self.scalar_steps = 0
        self.memory_work = 0

    def resolve_value(self, operand) -> DemandQueryResult:
        """Resolve one value and preserve budget failure as explicit state."""

        demand = self.owner
        if demand.active:
            raise RuntimeError(
                "A top-level demand query cannot start recursively"
            )
        accounting = demand.port.engine.accounting
        before_work = accounting.counts["worklist_iterations"]
        before_steps = demand.steps
        before_notes = len(demand.notes)
        started = time.monotonic()
        prior_cycles = demand.cycles
        demand.cycles = set()
        completeness = DemandCompleteness.COMPLETE
        diagnostics = []
        try:
            values = demand.value(operand)
            if any(
                demand.contains(value, demand.cycles) for value in values
            ):
                completeness = DemandCompleteness.INCOMPLETE
                diagnostics.append("Unresolved recurrence frontier")
        except self.incomplete_errors as error:
            completeness = DemandCompleteness.INCOMPLETE
            diagnostics.append(type(error).__name__ + ": " + str(error))
            definition = (
                demand.defs.get(operand.id)
                if hasattr(operand, "id")
                else None
            )
            origin = (
                definition[2].origin
                if definition is not None
                else demand.port.engine.origins[0].id
            )
            values = (
                demand.port.unknown(
                    operand.type,
                    origin,
                    "Incomplete demand query: " + str(error),
                ),
            )
        finally:
            demand.cycles = prior_cycles
        diagnostics.extend(
            str(note) for note in demand.notes[before_notes:]
        )
        cost = DemandQueryCost(
            demand.steps - before_steps,
            accounting.counts["worklist_iterations"] - before_work,
            time.monotonic() - started,
        )
        if completeness == DemandCompleteness.COMPLETE:
            self.completed += 1
        else:
            self.incomplete += 1
        self.scalar_steps += cost.scalar_steps
        self.memory_work += cost.memory_work
        return DemandQueryResult(
            tuple(values),
            completeness,
            tuple(dict.fromkeys(diagnostics)),
            cost,
        )

    def metrics(self) -> dict[str, int]:
        """Return deterministic aggregate query counters."""

        return {
            "queries_completed": self.completed,
            "queries_incomplete": self.incomplete,
            "query_scalar_steps": self.scalar_steps,
            "query_memory_work": self.memory_work,
        }

