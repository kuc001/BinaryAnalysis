"""Run the characterized P6 CIR iCall pass for the production CLI."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
import logging
import time

from emtaint.analysis.controlflow.targets import TargetGraphUpdater
from emtaint.analysis.framework.runtime import AnalysisRuntime
from emtaint.compat.legacy_icall_policy import legacy_maximum_address
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.core import ContextId, FunctionId
from emtaint.core.contracts import AnalysisScope, SemanticBudgets
from emtaint.debugging import (
    function_address_fields,
    log_event,
    progress_heartbeat,
)
from emtaint.frontends.program_index import ProgramIndex
from emtaint.ir.canonical import CIRModule
from emtaint.memory.image import ImageMemoryEngine
from emtaint.orchestration.legacy_cir_search import (
    CIRLegacySearch,
    LegacyFunctionResult,
    callee_first,
)
from emtaint.orchestration.program_search import (
    CIRProgramSearch,
    ProgramSearchResult,
)


LOGGER = logging.getLogger(__name__)
ImageSegment = tuple[int, bytes, int, int]
SectionRange = tuple[int, int]
InputSite = tuple[int, int]


def recover_icalls(
    *,
    module: CIRModule,
    index: ProgramIndex,
    segments: Sequence[ImageSegment],
    sections: Mapping[str, SectionRange],
    input_sites: Sequence[InputSite],
    body_hashes: Mapping[FunctionId, str],
    max_rounds: int = 4,
) -> tuple[
    AnalysisRuntime,
    ProgramSearchResult,
    tuple[dict[str, object], ...],
]:
    """Recover indirect targets and refine the call graph to a fixed point.

    Args:
        module: Combined CIR module containing every selected function body.
        index: Whole-program metadata, CFG collection, and initial call graph.
        segments: Immutable loader segments as ``(base, data, size, flags)``.
        sections: Named absolute-address intervals, including ``.text``.
        input_sites: ``(caller_address, callsite_address)`` annotations from IDA.
        body_hashes: Derived CIR body digest keyed by stable function identity.
        max_rounds: Hard cap for dependency-driven graph reanalysis rounds.

    Returns:
        The analysis runtime, fixed-point result, and per-function invocation
        metrics. Pending functions remain explicit in the result.
    """

    started = time.monotonic()
    base = index.program.image_base
    functions = {
        function.function_id: function for function in module.functions
    }
    origins = {
        function_id: tuple(
            origin
            for origin in module.origin_map
            if origin.point.function == function_id
        )
        for function_id in functions
    }

    runtime = AnalysisRuntime(index.program)
    runtime.session.replace_cg(index.cg)
    for cfg in index.cfgs:
        runtime.session.replace_cfg(cfg)

    input_callers = {caller for caller, _ in input_sites}
    summary_functions = {
        function_id
        for function_id in functions
        if function_id.rva + base not in input_callers
    }
    log_event(
        LOGGER,
        "icall.runtime.ready",
        level=logging.INFO,
        functions=len(functions),
        input_sites=len(input_sites),
        summary_functions=len(summary_functions),
        max_rounds=max_rounds,
        initial_cg_edges=len(index.cg.edges),
        initial_cfgs=len(index.cfgs),
    )

    text_start, text_end = sections[".text"]

    def is_code(address: int) -> bool:
        """Return whether an absolute address lies in the executable section."""

        return text_start <= address <= text_end

    data_sections = {".data", ".rodata", ".bss", ".got", ".init_array"}

    def is_data(address: int) -> bool:
        """Return whether an absolute address lies in a modeled data section."""

        return any(
            start <= address <= end
            for name, (start, end) in sections.items()
            if name in data_sections
        )

    invocations: list[dict[str, object]] = []

    def analyze(function_id: FunctionId) -> LegacyFunctionResult:
        """Analyze one function in the runtime's current graph revision."""

        function_started = time.monotonic()
        address = function_id.rva + base
        context = ContextId()
        scope = AnalysisScope.from_session(
            runtime.session,
            function_id,
            context,
        )
        engine = ImageMemoryEngine(
            scope,
            module.architecture,
            origins[function_id],
            segments,
            SemanticBudgets(
                sse_nodes=200_000,
                worklist_iterations=2_000_000,
            ),
            initial_policy="legacy-loader-snapshot",
        )
        port = MemoryRuntimePort(engine)
        runtime.bind_port(port, function_id, context)
        recipes = {}
        for candidate in functions:
            recipe = runtime.recipe_get(candidate, context)
            if recipe is not None:
                recipes[candidate] = recipe
        sites = [
            site
            for caller, site in input_sites
            if caller == address
        ]
        log_event(
            LOGGER,
            "icall.analysis.started",
            **function_address_fields(function_id.rva, base, legacy_field="va"),
            sites=len(sites),
            available_recipes=len(recipes),
            make_recipe=function_id in summary_functions,
            function_epoch=runtime.epochs[function_id],
            cg_revision=runtime.session.stamp.state_revision,
        )

        search = CIRLegacySearch(
            functions[function_id],
            origins[function_id],
            runtime.session.cfg(function_id),
            port,
            input_sites=sites,
            image_base=base,
            summaries=recipes,
            is_code=is_code,
            is_data=is_data,
            bounds={
                site: legacy_maximum_address(module.binary_sha256, site)
                for site in sites
            },
            body_token=body_hashes[function_id],
            make_recipe=function_id in summary_functions,
        )
        with progress_heartbeat(
            LOGGER,
            "icall.analysis.heartbeat",
            **function_address_fields(function_id.rva, base, legacy_field="va"),
            sites=len(sites),
            function_epoch=runtime.epochs[function_id],
        ):
            result = search.run()

        recipe_affected = frozenset()
        if result.recipe is not None:
            recipe_affected = runtime.recipe_put(
                function_id,
                context,
                result.recipe,
            )
        invocation = {
            "function": address,
            "steps": result.steps,
            "metrics": result.metrics,
            "pending": len(result.pending),
        }
        invocations.append(invocation)
        log_event(
            LOGGER,
            "icall.analysis.completed",
            **function_address_fields(function_id.rva, base, legacy_field="va"),
            steps=result.steps,
            sites=len(result.sites),
            target_facts=len(result.targets),
            target_values=sum(len(fact.targets) for fact in result.targets),
            pending=len(result.pending),
            recipe_nodes=(
                0 if result.recipe is None else len(result.recipe.nodes)
            ),
            recipe_returns=(
                0 if result.recipe is None else len(result.recipe.returns)
            ),
            recipe_invalidated=len(recipe_affected),
            metrics=result.metrics,
            wall_seconds=time.monotonic() - function_started,
        )
        return result

    updater = TargetGraphUpdater(runtime, module.origin_map)
    log_event(
        LOGGER,
        "icall.fixed_point.started",
        level=logging.INFO,
        functions=len(functions),
        max_rounds=max_rounds,
    )
    result = CIRProgramSearch(
        runtime,
        updater,
        analyze,
        max_rounds=max_rounds,
        order=lambda todo: callee_first(todo, runtime.session.cg),
        image_base=base,
    ).run(functions)

    log_event(
        LOGGER,
        "icall.fixed_point.completed",
        level=logging.INFO,
        rounds=result.rounds,
        invocations=result.invocations,
        pending=len(result.pending),
        runtime_events=len(runtime.events),
        unmapped_targets=len(updater.unmapped),
        final_cg_edges=len(runtime.session.cg.edges),
        wall_seconds=time.monotonic() - started,
    )
    return runtime, result, tuple(invocations)
