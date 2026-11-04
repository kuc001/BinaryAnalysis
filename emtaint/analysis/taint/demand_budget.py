"""Query-local budget and lifecycle management for P7 taint demand."""

from contextlib import contextmanager
import time

from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.procedures.legacy import lookup


LOCAL_SINK_OPERATIONS = frozenset((
    "copy",
    "format_output",
    "format_input",
    "command",
    "command_argv",
))


class QueryBudgetController:
    """Manage query shares without owning analysis state.

    All counters remain on the legacy owner so replay metrics and callers see
    the same fields.  The controller only centralizes formulas and guarantees
    restoration of temporary accounting/validation hooks after exceptions.
    """

    def __init__(self, owner):
        self.owner = owner

    def begin_query(self, query=None):
        """Assign the unchanged taint, scalar, memory, and wall shares."""
        owner = self.owner
        remaining = max(1, owner.queries_remaining)
        share = max(
            1,
            min(owner.max_dependencies * 4, owner.max_steps // 16),
            (owner.max_steps - owner.steps) // remaining,
        )
        owner.queries_remaining = max(0, owner.queries_remaining - 1)
        owner.query_step_limit = owner.steps + share
        demand = owner.demand
        demand.query_scalar_limit = demand.steps + max(
            1,
            demand.budget.steps // 16,
            (demand.budget.steps - demand.steps) // remaining,
        )
        small_local_pool = False
        if (
            query is not None
            and query.kind == "call"
            and not owner.inherited_sink_count
            and 0 < owner.local_sink_call_count <= 8
        ):
            rule = lookup(owner.demand.call_name(query.effect))
            small_local_pool = bool(
                rule and rule.operation in LOCAL_SINK_OPERATIONS
            )
            if small_local_pool:
                owner.query_step_limit = max(
                    owner.query_step_limit,
                    owner.steps
                    + min(
                        owner.max_steps // 8,
                        (owner.max_steps - owner.steps)
                        // owner.local_sink_call_count,
                    ),
                )
                demand.query_scalar_limit = max(
                    demand.query_scalar_limit,
                    demand.steps
                    + min(
                        demand.budget.steps // 4,
                        (demand.budget.steps - demand.steps)
                        // owner.local_sink_call_count,
                    ),
                )
        accounting = owner.port.engine.accounting
        used = accounting.counts["worklist_iterations"]
        owner.query_work_limit = used + max(
            1,
            accounting.budgets.worklist_iterations // 16,
            (accounting.budgets.worklist_iterations - used) // remaining,
        )
        if owner.function_deadline is not None:
            now = time.monotonic()
            minimum = max(
                0,
                (owner.function_deadline - owner.function_started) / 16,
            )
            if query is not None and query.kind == "call":
                rule = lookup(owner.demand.call_name(query.effect))
                if rule and rule.operation in LOCAL_SINK_OPERATIONS:
                    minimum = max(
                        minimum,
                        (owner.function_deadline - owner.function_started) / 3,
                    )
            owner.query_clock_limit = now + max(
                minimum,
                (owner.function_deadline - now) / remaining,
            )
            if small_local_pool:
                owner.query_clock_limit = owner.function_deadline

    def clear_query_limits(self):
        """Clear all query-local ceilings while retaining global budgets."""
        owner = self.owner
        owner.query_step_limit = None
        owner.query_work_limit = None
        owner.query_clock_limit = None
        owner.demand.query_scalar_limit = None

    def check_query_clock(self):
        """Raise the historical query-dimension wall-share failure."""
        limit = self.owner.query_clock_limit
        if limit is not None and time.monotonic() > limit:
            raise DemandLimit(
                "Independent query wall share exhausted", dimension="query"
            )

    @contextmanager
    def argument_preparation(self, call, index):
        """Temporarily disable local shares for one reusable argument read."""
        owner = self.owner
        shared = owner.current_query is not None
        scalar = owner.demand.steps
        work = owner.port.engine.accounting.counts["worklist_iterations"]
        started = time.monotonic()
        limits = (
            owner.demand.query_scalar_limit,
            owner.query_work_limit,
            owner.query_clock_limit,
        )
        if shared:
            owner.demand.query_scalar_limit = None
            owner.query_work_limit = None
            owner.query_clock_limit = None
        state = {"status": "complete"}
        try:
            yield state
        finally:
            if shared:
                scalar_cost = owner.demand.steps - scalar
                work_cost = (
                    owner.port.engine.accounting.counts["worklist_iterations"]
                    - work
                )
                seconds = time.monotonic() - started
                owner.demand.query_scalar_limit = (
                    None if limits[0] is None else limits[0] + scalar_cost
                )
                owner.query_work_limit = (
                    None if limits[1] is None else limits[1] + work_cost
                )
                owner.query_clock_limit = (
                    None if limits[2] is None else limits[2] + seconds
                )
                owner.argument_preparations.append({
                    "origin": call.origin,
                    "slot": index,
                    "scalar_steps": scalar_cost,
                    "memory_work": work_cost,
                    "seconds": seconds,
                    "status": state["status"],
                })

    @contextmanager
    def accounting_observer(self):
        """Install and reliably restore the query-aware accounting hook."""
        owner = self.owner
        accounting = owner.port.engine.accounting
        previous = accounting.observer

        def observer(dimension, observed):
            if previous is not None:
                previous(dimension, observed)
            self.check_query_clock()
            if (
                dimension == "worklist_iterations"
                and owner.query_work_limit is not None
                and observed > owner.query_work_limit
            ):
                raise DemandLimit(
                    "Independent memory worklist query share exhausted",
                    dimension="query",
                )

        accounting.observer = observer
        try:
            yield
        finally:
            accounting.observer = previous

    @contextmanager
    def validation_wrapper(self):
        """Install and reliably restore wall checks around port validation."""
        owner = self.owner
        validate = owner.port.validate_current

        def scoped_validate():
            validate()
            self.check_query_clock()

        owner.port.validate_current = scoped_validate
        try:
            yield
        finally:
            owner.port.validate_current = validate

    @contextmanager
    def query_lifecycle(self):
        """Scope both temporary hooks and clear local limits on exit."""
        try:
            with self.accounting_observer(), self.validation_wrapper():
                yield
        finally:
            self.clear_query_limits()
