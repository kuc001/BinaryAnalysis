"""Detached public models shared by P7 taint-demand components.

These immutable records cross procedure and query boundaries.  Their field
order, defaults, equality, hashing, and representation are replay contracts;
keep structural changes synchronized with compatibility fixtures.
"""

from dataclasses import dataclass, field
import hashlib


@dataclass(frozen=True)
class ConstraintRecipe:
    """Name a detached constraint recipe while retaining its runtime value.

    ``key`` is the stable evidence identity.  ``value`` is intentionally
    excluded from comparison, hashing, and repr because it may contain
    session-local compiled objects.
    """

    key: str
    value: object = field(compare=False, hash=False, repr=False)

    @classmethod
    def wrap(cls, value):
        """Derive the historical SHA-256 key from ``repr(value)``."""
        return cls(
            hashlib.sha256(repr(value).encode("utf8")).hexdigest(), value
        )


@dataclass(frozen=True)
class TaintDependency:
    """Describe one detached source, argument, global, or unknown flow.

    Paths remain part of dependency identity until ``source_antichain``
    records an explicit covered-to-covering relation.  The ordering helper
    deliberately excludes paths; the antichain owns their semantic collapse.
    Constraint, guard, handle, offset, and access metadata retain the exact
    order in which the legacy analysis produced them.
    """

    kind: str
    value: object
    constraints: tuple = ()
    path: tuple = field(default=())
    uncertain: bool = False
    guards: tuple = ()
    handles: tuple = ()
    offset: int | None = 0
    recipes: tuple = ()
    access_width: int = 8
    byte_access: bool = False
    unresolved_constraints: bool = False
    constraint_type: int = 0


@dataclass(frozen=True)
class DeferredFormatArgument:
    """Select a va_list candidate after a caller supplies the format.

    ``format_slot`` belongs to the current detached procedure signature;
    ``position`` is the legacy FormatParser parameter index.  The nested
    dependency remains detached, so no caller-scoped SSE/APG identity crosses
    the summary boundary.
    """

    format_slot: int
    position: int
    dependency: TaintDependency


@dataclass(frozen=True)
class BufferDestination:
    """Describe a possible copy destination and its byte offset."""

    kind: str
    value: object
    offset: int | None = 0


@dataclass(frozen=True)
class SinkRequirement:
    """Record the detached dependencies required by one sink operation.

    ``dependencies`` is the data channel and ``length_dependencies`` is the
    independent length channel.  Their separation is part of the P7 replay
    contract.  Destinations and guards remain may-evidence, not proof of a
    confirmed vulnerability.
    """

    function: int
    site: int
    name: str
    kind: str
    offsets: tuple
    dependencies: tuple
    origin: str
    constraints: tuple = ()
    guards: tuple = ()
    destinations: tuple = ()
    weak_kind: str = "copy"
    length_dependencies: tuple = ()


@dataclass(frozen=True)
class TaintProcedureSummary:
    """Contain detached may-flow results for one procedure.

    ``pending`` marks incomplete work and must never be interpreted as a
    clean result.  ``None`` for scalar or global outputs means that channel
    was not evaluated; an empty tuple means it was evaluated and found empty.
    """

    function: int
    returns: tuple = ()
    outputs: tuple = ()
    sinks: tuple = ()
    pending: tuple = ()
    tables: tuple = ()
    scalar_returns: tuple | None = None
    global_outputs: tuple | None = None


def dependency_order(dep):
    """Return the historical deterministic dependency ordering key."""
    return (
        dep.kind,
        repr(dep.value),
        repr(dep.constraints),
        dep.uncertain,
        repr(dep.guards),
        repr(dep.handles),
        repr(dep.offset),
        repr(dep.recipes),
        dep.access_width,
        dep.byte_access,
        dep.unresolved_constraints,
        dep.constraint_type,
    )


def sink_order(sink):
    """Return the historical deterministic sink ordering key."""
    return (
        sink.function,
        sink.site,
        sink.name,
        sink.kind,
        repr(sink.offsets),
        sink.origin,
        repr(sink.constraints),
        repr(sink.guards),
        repr(sink.destinations),
        sink.weak_kind,
    )
