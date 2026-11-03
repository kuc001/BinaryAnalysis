"""Legacy demand/summary scheduling through CIR and memory ports.

Loader bytes, source CFG edges and policy bounds are explicit frontend inputs.
This module does not access native IR, files, archived targets or global state.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import asdict, dataclass
import logging
import time

from emtaint.analysis.controlflow.legacy_tables import (
    LegacyTableCollector,
    LegacyTableEvidence,
)
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
from emtaint.core.contracts import Assessment, Origin, Record
from emtaint.debugging import function_address_fields, log_event
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
class CallSiteAnalysisResult(Record):
    """Typed result and evidence boundary for one requested iCall site.

    ``site`` is the absolute virtual address used by IDA metadata. The core
    fields retain the target candidates, evidence, incomplete remainder and
    per-site assessment needed by later evidence-chain validation. Additional
    fields preserve existing P6 coverage and diagnostic information.
    """

    site: int
    origin: str
    targets: tuple[int, ...]
    evidence: tuple[LegacyTableEvidence, ...]
    unknown_remainder: bool
    assessment: Assessment
    demand_steps: int
    cfg_reachable: bool
    classification: str | None = None
    expressions: tuple[str, ...] = ()
    rule_ids: tuple[str, ...] = ()
    memory_version: str | None = None
    error: str | None = None

    def __post_init__(self) -> None:
        """Validate stable address, target ordering and variant invariants."""

        super().__post_init__()
        if self.site < 0 or self.demand_steps < 0:
            raise ValueError("Site address and demand steps must be non-negative")
        if self.targets != tuple(sorted(set(self.targets))):
            raise ValueError("Call-site targets must be sorted and unique")
        if self.classification is not None and self.error is not None:
            raise ValueError("A classified site cannot also be an analysis error")
        if (
            self.classification is None
            and self.error is None
            and self.memory_version is None
        ):
            raise ValueError("Analyzed call site requires a MemoryVersion")

    def to_legacy_dict(self) -> dict[str, object]:
        """Return the exact pre-DTO site-coverage shape for P6 compatibility."""

        if self.classification is not None:
            return {
                "site": self.site,
                "classification": self.classification,
                "origin": self.origin,
                "cfg_reachable": self.cfg_reachable,
                "targets": list(self.targets),
            }
        row: dict[str, object] = {
            "site": self.site,
            "origin": self.origin,
            "cfg_reachable": self.cfg_reachable,
            "targets": list(self.targets),
        }
        if self.error is not None:
            row.update(
                error=self.error,
                unknown_remainder=self.unknown_remainder,
            )
            return row
        row.update(
            expressions=list(self.expressions),
            evidence=[item.to_legacy_dict() for item in self.evidence],
            unknown_remainder=self.unknown_remainder,
            rule_ids=list(self.rule_ids),
            memory_version=self.memory_version,
        )
        return row

    def to_evidence_dict(self) -> dict[str, object]:
        """Return the normalized typed shape for future evidence-chain output."""

        return {
            "site": self.site,
            "origin": self.origin,
            "targets": list(self.targets),
            "evidence": [item.to_legacy_dict() for item in self.evidence],
            "unknown_remainder": self.unknown_remainder,
            "assessment": asdict(self.assessment),
            "demand_steps": self.demand_steps,
            "cfg_reachable": self.cfg_reachable,
            "classification": self.classification,
            "expressions": list(self.expressions),
            "rule_ids": list(self.rule_ids),
            "memory_version": self.memory_version,
            "error": self.error,
        }


@dataclass(frozen=True)
class LegacyFunctionResult:
    """Detached result of one function-local CIR demand search."""

    targets: tuple[TargetFact, ...]
    pending: tuple[object, ...]
    assessment: Assessment
    steps: int
    visited_blocks: tuple[BlockId, ...]
    sites: tuple[CallSiteAnalysisResult, ...]
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
        function_fields = function_address_fields(
            self.function.function_id.rva,
            self.image_base,
            legacy_field="va",
        )
        log_event(
            LOGGER,
            "icall.cir_search.started",
            **function_fields,
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
        rows: list[CallSiteAnalysisResult] = []
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
            **function_fields,
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
                        CallSiteAnalysisResult(
                            site=site_address,
                            origin=effect.origin,
                            targets=(),
                            evidence=(),
                            unknown_remainder=False,
                            assessment=Assessment.complete(),
                            demand_steps=demand.steps,
                            cfg_reachable=block.id in reachable,
                            classification=(
                                "IDA annotation / CIR native return"
                            ),
                        )
                    )
                    log_event(
                        LOGGER,
                        "icall.cir_search.site.return",
                        **function_fields,
                        site=hex(site_address),
                        site_rva=hex(point.instruction_rva),
                        site_va=hex(site_address),
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
                collector = None
                roots = ()
                error_message = None
                site_started = time.monotonic()
                log_event(
                    LOGGER,
                    "icall.cir_search.site.started",
                    **function_fields,
                    site=hex(site_address),
                    site_rva=hex(point.instruction_rva),
                    site_va=hex(site_address),
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
                    log_event(
                        LOGGER,
                        "icall.cir_search.site.completed",
                        **function_fields,
                        site=hex(site_address),
                        site_rva=hex(point.instruction_rva),
                        site_va=hex(site_address),
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
                    error_message = str(error)
                    log_event(
                        LOGGER,
                        "icall.cir_search.site.incomplete",
                        level=logging.WARNING,
                        **function_fields,
                        site=hex(site_address),
                        site_rva=hex(point.instruction_rva),
                        site_va=hex(site_address),
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
                rows.append(
                    CallSiteAnalysisResult(
                        site=site_address,
                        origin=effect.origin,
                        targets=values,
                        evidence=(
                            ()
                            if collector is None
                            else tuple(collector.evidence)
                        ),
                        unknown_remainder=True,
                        assessment=assessment,
                        demand_steps=demand.steps,
                        cfg_reachable=block.id in reachable,
                        expressions=tuple(root.key for root in roots),
                        rule_ids=tuple(sorted(demand.rules)),
                        memory_version=initial.memory.key,
                        error=error_message,
                    )
                )

        if skipped_effects:
            log_event(
                LOGGER,
                "icall.cir_search.non_target_effects.skipped",
                **function_fields,
                total=sum(skipped_effects.values()),
                by_type=dict(sorted(skipped_effects.items())),
            )

        if self.make_recipe:
            recipe = self._compile_recipe(
                demand,
                notes,
                pending,
            )
        if demand.notes:
            notes.append(over("; ".join(sorted(set(demand.notes))), True))
        if len(rows) < len(self.input_sites):
            missing = self.input_sites - {row.site for row in rows}
            pending.extend(("missing-site", site) for site in sorted(missing))
            notes.append(over("Input sites lack a CIR call/return terminal", True))
            log_event(
                LOGGER,
                "icall.cir_search.sites.missing",
                level=logging.WARNING,
                **function_fields,
                sites=[hex(site) for site in sorted(missing)],
            )
        snapshot = port.engine.snapshot()
        notes.append(snapshot.assessment)
        if self.cfg.status != Completeness.COMPLETE:
            notes.append(
                over("Source CFG coverage/guard feasibility remains incomplete", True)
            )
        result = LegacyFunctionResult(
            targets=tuple(facts),
            pending=tuple(pending),
            assessment=combine(notes),
            steps=demand.steps,
            visited_blocks=tuple(
                sorted(reachable, key=lambda block: block.token)
            ),
            sites=tuple(rows),
            recipe=recipe,
            snapshot=snapshot,
            metrics=port.metrics(),
            reference_recipes=tuple(reference_recipes),
        )
        log_event(
            LOGGER,
            "icall.cir_search.completed",
            **function_fields,
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
        notes: list[object],
        pending: list[object],
    ) -> object | None:
        """Compile return/global effects into a detached caller recipe."""

        roots = []
        stores = []
        function_fields = function_address_fields(
            self.function.function_id.rva,
            self.image_base,
            legacy_field="va",
        )
        log_event(
            LOGGER,
            "icall.cir_search.recipe.started",
            **function_fields,
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
                **function_fields,
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
                **function_fields,
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
