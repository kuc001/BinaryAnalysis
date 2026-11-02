"""Legacy demand/summary scheduling through CIR and memory ports.

Loader bytes, source CFG edges and policy bounds are explicit frontend inputs.
This module does not access native IR, files, archived targets or global state.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
import logging
import time

from emtaint.analysis.controlflow.legacy_tables import LegacyTableCollector
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.dataflow.legacy_demand import (
    DemandBudget,
    DemandLimit,
    LegacyDemand,
)
from emtaint.analysis.framework.state import TargetFact
from emtaint.analysis.framework.summaries import compile_recipe
from emtaint.core import BlockId, CallSiteId, Completeness, FunctionId
from emtaint.core.contracts import Origin
from emtaint.debugging import log_event
from emtaint.graph import CallGraph, ControlFlowGraph
from emtaint.ir.canonical import (
    CIRFunction,
    CallEffect,
    IndirectTarget,
    JumpEffect,
    ReturnEffect,
    StoreEffect,
)
from emtaint.memory.engine import combine, over
from emtaint.memory.policies import BudgetExceeded


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class LegacyFunctionResult:
    """Detached result of one function-local CIR demand search."""

    targets: tuple[TargetFact, ...]
    pending: tuple[object, ...]
    assessment: object
    steps: int
    visited_blocks: tuple[BlockId, ...]
    sites: tuple[dict[str, object], ...]
    recipe: object | None
    snapshot: object
    metrics: object
    reference_recipes: tuple[object, ...] = ()


class CIRLegacySearch:
    """Recover iCall targets and optional callee recipes from one CIR function.

    Args:
        function: Immutable CIR function body to analyze.
        origins: CIR origin records belonging to ``function``.
        cfg: Current versioned function control-flow graph.
        port: Memory/SSE query adapter scoped to this function and context.
        input_sites: Absolute iCall addresses requested by IDA metadata.
        image_base: Absolute load base used for RVA conversion.
        summaries: Detached callee recipes available at this graph revision.
        is_code: Predicate for candidate executable addresses.
        is_data: Predicate for candidate data/table addresses.
        bounds: Optional legacy maximum-address policy per iCall site.
        budget: Scalar demand step/depth limits.
        body_token: Stable CIR body digest used in recipe provenance.
        make_recipe: Whether to export return/global effects for callers.
    """

    def __init__(
        self,
        function: CIRFunction,
        origins: Sequence[Origin],
        cfg: ControlFlowGraph,
        port: object,
        *,
        input_sites: Sequence[int] = (),
        image_base: int = 0,
        summaries: Mapping[FunctionId, object] | None = None,
        is_code: Callable[[int], bool] | None = None,
        is_data: Callable[[int], bool] | None = None,
        bounds: Mapping[int, int] | None = None,
        budget: DemandBudget = DemandBudget(steps=250_000, depth=500),
        body_token: str = "",
        make_recipe: bool = True,
    ) -> None:
        self.function = function
        self.origins = {origin.id: origin for origin in origins}
        self.cfg = cfg
        self.port = port
        self.input_sites = frozenset(input_sites)
        self.image_base = image_base
        self.summaries = summaries or {}
        self.bounds = bounds or {}
        self.budget = budget
        self.is_code = is_code or (lambda _value: False)
        self.is_data = is_data or (lambda _value: False)
        self.body_token = body_token
        self.make_recipe = make_recipe

    def run(self) -> LegacyFunctionResult:
        """Execute backward demand, table collection and recipe compilation."""

        started = time.monotonic()
        function_address = self.image_base + self.function.function_id.rva
        log_event(
            LOGGER,
            "icall.cir_search.started",
            function=hex(function_address),
            blocks=len(self.function.blocks),
            input_sites=len(self.input_sites),
            make_recipe=self.make_recipe,
        )
        port = self.port
        flow = CIRAccurateDataFlow(port)
        initial = legacy_entry(flow)
        demand = LegacyDemand(
            self.function,
            port,
            self.cfg,
            initial,
            budget=self.budget,
            summaries=self.summaries,
        )
        facts: list[TargetFact] = []
        rows: list[dict[str, object]] = []
        pending: list[object] = []
        notes = []
        recipe = None
        reference_recipes = []
        skipped_effects: Counter[str] = Counter()

        reachable = {self.cfg.entry}
        todo = [self.cfg.entry]
        while todo:
            node = todo.pop()
            for target in self.cfg.successors(node):
                if target not in reachable:
                    reachable.add(target)
                    todo.append(target)
        log_event(
            LOGGER,
            "icall.cir_search.reachability.completed",
            function=hex(function_address),
            cfg_nodes=len(self.cfg.nodes),
            cfg_edges=len(self.cfg.edges),
            reachable_blocks=len(reachable),
            unreachable_blocks=len(self.cfg.nodes) - len(reachable),
        )

        for block in self.function.blocks:
            for effect in block.effects:
                origin = self.origins[effect.origin]
                point = origin.point
                site_address = (
                    None
                    if point.instruction_rva is None
                    else self.image_base + point.instruction_rva
                )
                if site_address not in self.input_sites:
                    continue
                if isinstance(effect, ReturnEffect):
                    rows.append(
                        {
                            "site": site_address,
                            "classification": "IDA annotation / CIR native return",
                            "origin": effect.origin,
                            "cfg_reachable": block.id in reachable,
                            "targets": [],
                        }
                    )
                    log_event(
                        LOGGER,
                        "icall.cir_search.site.return",
                        function=hex(function_address),
                        site=hex(site_address),
                        origin=effect.origin,
                        cfg_reachable=block.id in reachable,
                    )
                    continue
                operand = self._target_operand(effect)
                if operand is None:
                    skipped_effects[type(effect).__name__] += 1
                    continue
                site = (
                    effect.site
                    if isinstance(effect, CallEffect)
                    else CallSiteId(point)
                )
                row: dict[str, object] = {
                    "site": site_address,
                    "origin": effect.origin,
                    "cfg_reachable": block.id in reachable,
                }
                collector = None
                site_started = time.monotonic()
                log_event(
                    LOGGER,
                    "icall.cir_search.site.started",
                    function=hex(function_address),
                    site=hex(site_address),
                    origin=effect.origin,
                    cfg_reachable=block.id in reachable,
                    maximum_address=self.bounds.get(site_address),
                )
                try:
                    roots = demand.value(operand)
                    collector = LegacyTableCollector(
                        demand,
                        self.is_code,
                        self.is_data,
                    )
                    reference_recipes.append(
                        (
                            site_address,
                            compile_recipe(
                                demand,
                                roots,
                                provenance=(
                                    self.body_token,
                                    "Same CIR demand roots for reference replay",
                                ),
                            ),
                        )
                    )
                    values = tuple(
                        sorted(
                            {
                                value
                                for root in roots
                                for value in collector.collect(
                                    root,
                                    maximum_address=self.bounds.get(site_address),
                                )
                            }
                        )
                    )
                    assessment = over(
                        "Legacy candidate collection over explicit initial loader "
                        "bytes; runtime feasibility/memory remainder retained",
                        True,
                    )
                    row.update(
                        targets=list(values),
                        expressions=[root.key for root in roots],
                        evidence=collector.evidence,
                        unknown_remainder=True,
                        rule_ids=sorted(demand.rules),
                        memory_version=initial.memory.key,
                    )
                    log_event(
                        LOGGER,
                        "icall.cir_search.site.completed",
                        function=hex(function_address),
                        site=hex(site_address),
                        roots=len(roots),
                        targets=len(values),
                        demand_steps=demand.steps,
                        rules=len(demand.rules),
                        wall_seconds=time.monotonic() - site_started,
                    )
                except (DemandLimit, BudgetExceeded, RecursionError) as error:
                    values = (
                        tuple(sorted(collector.partial_targets))
                        if collector is not None
                        else ()
                    )
                    assessment = over(
                        type(error).__name__ + ": " + str(error),
                        True,
                    )
                    pending.append((site, assessment.diagnostics))
                    row.update(
                        targets=list(values),
                        error=str(error),
                        unknown_remainder=True,
                    )
                    log_event(
                        LOGGER,
                        "icall.cir_search.site.incomplete",
                        level=logging.WARNING,
                        function=hex(function_address),
                        site=hex(site_address),
                        error_type=type(error).__name__,
                        error_message=str(error),
                        partial_targets=len(values),
                        demand_steps=demand.steps,
                        wall_seconds=time.monotonic() - site_started,
                    )
                facts.append(
                    TargetFact(
                        site,
                        values,
                        "icall",
                        "may" if values else "unknown",
                        False,
                        initial.memory,
                        (),
                        effect.origin,
                        assessment,
                        "Legacy CIR use/def, callsite recipe substitution and "
                        "MemoryQueryPort loader-table candidates",
                    )
                )
                notes.append(assessment)
                rows.append(row)

        if skipped_effects:
            log_event(
                LOGGER,
                "icall.cir_search.non_target_effects.skipped",
                function=hex(function_address),
                total=sum(skipped_effects.values()),
                by_type=dict(sorted(skipped_effects.items())),
            )

        if self.make_recipe:
            recipe = self._compile_recipe(
                demand,
                function_address,
                notes,
                pending,
            )
        if demand.notes:
            notes.append(over("; ".join(sorted(set(demand.notes))), True))
        if len(rows) < len(self.input_sites):
            missing = self.input_sites - {row["site"] for row in rows}
            pending.extend(("missing-site", site) for site in sorted(missing))
            notes.append(over("Input sites lack a CIR call/return terminal", True))
            log_event(
                LOGGER,
                "icall.cir_search.sites.missing",
                level=logging.WARNING,
                function=hex(function_address),
                sites=[hex(site) for site in sorted(missing)],
            )
        snapshot = port.engine.snapshot()
        notes.append(snapshot.assessment)
        if self.cfg.status != Completeness.COMPLETE:
            notes.append(
                over("Source CFG coverage/guard feasibility remains incomplete", True)
            )
        result = LegacyFunctionResult(
            tuple(facts),
            tuple(pending),
            combine(notes),
            demand.steps,
            tuple(sorted(reachable, key=lambda block: block.token)),
            tuple(rows),
            recipe,
            snapshot,
            port.metrics(),
            tuple(reference_recipes),
        )
        log_event(
            LOGGER,
            "icall.cir_search.completed",
            function=hex(function_address),
            visited_blocks=len(result.visited_blocks),
            target_facts=len(result.targets),
            pending=len(result.pending),
            demand_steps=result.steps,
            metrics=result.metrics,
            wall_seconds=time.monotonic() - started,
        )
        return result

    @staticmethod
    def _target_operand(effect: object) -> object | None:
        """Return the symbolic target operand of an indirect call or jump."""

        if isinstance(effect, CallEffect) and isinstance(
            effect.target,
            IndirectTarget,
        ):
            return effect.target.address
        if isinstance(effect, JumpEffect) and not isinstance(effect.target, BlockId):
            return effect.target
        return None

    def _compile_recipe(
        self,
        demand: LegacyDemand,
        function_address: int,
        notes: list[object],
        pending: list[object],
    ) -> object | None:
        """Compile return/global effects into a detached caller recipe."""

        roots = []
        stores = []
        log_event(
            LOGGER,
            "icall.cir_search.recipe.started",
            function=hex(function_address),
        )
        try:
            for block in self.function.blocks:
                for effect in block.effects:
                    if isinstance(effect, ReturnEffect):
                        for value in effect.values:
                            roots.extend(demand.value(value))
            for block in self.function.blocks:
                for effect in block.effects:
                    if not isinstance(effect, StoreEffect):
                        continue
                    binding = demand.local_address(effect.address)
                    if binding is not None and binding[0].region == "stack":
                        continue
                    stores.append(
                        (
                            effect,
                            demand.value(effect.address),
                            demand.value(effect.value),
                        )
                    )
            recipe = None
            if roots or stores:
                recipe = compile_recipe(
                    demand,
                    roots,
                    stores=stores,
                    provenance=(
                        self.body_token,
                        "Actual CIR callee use/def/return recipe",
                    ),
                )
            log_event(
                LOGGER,
                "icall.cir_search.recipe.completed",
                function=hex(function_address),
                return_roots=len(roots),
                stores=len(stores),
                recipe_nodes=0 if recipe is None else len(recipe.nodes),
                recipe_returns=0 if recipe is None else len(recipe.returns),
            )
            return recipe
        except (DemandLimit, BudgetExceeded, RecursionError) as error:
            notes.append(over("Procedure recipe incomplete: " + str(error), True))
            pending.append(("recipe", str(error)))
            log_event(
                LOGGER,
                "icall.cir_search.recipe.incomplete",
                level=logging.WARNING,
                function=hex(function_address),
                error_type=type(error).__name__,
                error_message=str(error),
                demand_steps=demand.steps,
            )
            return None


def callee_first(
    functions: Iterable[FunctionId],
    graph: CallGraph,
) -> tuple[FunctionId, ...]:
    """Return deterministic dependency postorder; cycles await reanalysis."""

    functions = frozenset(functions)
    children = {function: set() for function in functions}
    for edge in graph.edges:
        if edge.site.function in functions and edge.target in functions:
            children[edge.site.function].add(edge.target)
    done = set()
    visiting = set()
    result = []
    for root in sorted(functions, key=lambda function: function.rva):
        pending = [(root, False)]
        while pending:
            current, ready = pending.pop()
            if current in done:
                continue
            if ready:
                visiting.discard(current)
                done.add(current)
                result.append(current)
                continue
            if current in visiting:
                continue
            visiting.add(current)
            pending.append((current, True))
            pending.extend(
                (child, False)
                for child in sorted(
                    children[current],
                    key=lambda function: function.rva,
                    reverse=True,
                )
                if child not in visiting and child not in done
            )
    return tuple(result)


@dataclass(frozen=True)
class EngineAttempt:
    """Describe the primary engine attempt and the engine that produced output."""

    active_engine: str
    primary: object
    result: object
    reason: str = ""


def run_with_legacy_fallback(
    apg: Callable[[], object],
    legacy: Callable[[], object] | None,
) -> EngineAttempt:
    """Run a supplied legacy fallback, never an archived-output substitute."""

    attempt = None
    try:
        result = apg()
        attempt = result
        if result.pending:
            raise DemandLimit("APG attempt has unresolved execution frontier")
        return EngineAttempt("apg", result, result)
    except (DemandLimit, BudgetExceeded, RecursionError) as error:
        if legacy is None:
            raise RuntimeError("Legacy fallback runner is unavailable") from error
        return EngineAttempt("legacy", attempt, legacy(), str(error))
