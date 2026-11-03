"""Run source-annotated alias checks against a native benchmark binary.

The source markers are expectations, never analysis inputs.  Marker calls in
the binary provide only the two queried pointer values and the observation
site.  Values are reconstructed backwards with ``ProcedureDemand``; direct
callee stores are exported as detached recipes and instantiated at the caller
so a strong update such as ``*k = *s`` can affect the later query.
"""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re
import tempfile

from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.framework.summaries import compile_recipe
from emtaint.analysis.taint.demand import ProcedureDemand
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.core import ContextId
from emtaint.core.contracts import AnalysisScope, SemanticBudgets
from emtaint.frontends.angr_vex import AngrVexFrontend
from emtaint.frontends.loader_image import relocated_image
from emtaint.ir.canonical import (
    CallEffect,
    DirectTarget,
    ReturnEffect,
    StoreEffect,
)
from emtaint.memory import AliasKind
from emtaint.memory.image import ImageMemoryEngine


MARKERS = ("NOALIAS", "MAYALIAS", "MUSTALIAS")
_MARKER_PATTERN = re.compile(
    r"\b(NOALIAS|MAYALIAS|MUSTALIAS)\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)"
)


@dataclass(frozen=True)
class AliasExpectation:
    """One active source marker and its human-readable operands."""

    kind: str
    line: int
    left: str
    right: str


@dataclass(frozen=True)
class AliasObservation:
    """One independently computed binary alias result."""

    function: str
    site: int
    marker: str
    predicted: str
    expected: str | None
    source_line: int | None
    left: str | None
    right: str | None
    alias_kinds: tuple[str, ...]
    evidence: tuple[str, ...]
    complete: bool

    @property
    def matched(self) -> bool | None:
        """Return expectation agreement, or None without a source marker."""

        return None if self.expected is None else self.predicted == self.expected


@dataclass(frozen=True)
class AliasBenchmarkReport:
    """Identity, coverage, and observations for one source/binary pair."""

    source: str
    binary: str
    binary_sha256: str
    image_base: int
    functions: tuple[str, ...]
    expectations: tuple[AliasExpectation, ...]
    observations: tuple[AliasObservation, ...]
    diagnostics: tuple[str, ...] = ()

    @property
    def matched(self) -> int:
        return sum(item.matched is True for item in self.observations)

    @property
    def total(self) -> int:
        return len(self.expectations)

    def as_dict(self) -> dict[str, object]:
        """Return a stable JSON-ready representation."""

        return {
            "source": self.source,
            "binary": self.binary,
            "binary_sha256": self.binary_sha256,
            "image_base": self.image_base,
            "functions": list(self.functions),
            "expectations": [vars(item) for item in self.expectations],
            "observations": [
                {
                    **vars(item),
                    "matched": item.matched,
                    "alias_kinds": list(item.alias_kinds),
                    "evidence": list(item.evidence),
                }
                for item in self.observations
            ],
            "matched": self.matched,
            "total": self.total,
            "diagnostics": list(self.diagnostics),
        }


@dataclass(frozen=True)
class _LiftedFunction:
    name: str
    function: object
    cfg: object
    origins: tuple
    architecture: object


class _AliasProcedureDemand(ProcedureDemand):
    """Enable ABI stack proofs only for the alias benchmark client.

    Frozen LegacyDemand recognizes the ARM spelling ``sp``.  Native benchmark
    binaries can use another ABI stack register, so this client falls back to
    the proof-carrying normalizer already owned by ProcedureDemand.  Unknown
    offsets remain unknown and all alias decisions still go through the
    MemoryQueryPort.
    """

    def local_address(self, operand, seen=frozenset()):
        binding = super().local_address(operand, seen)
        if binding is not None and not (
                binding[0].region == "stack" and binding[1] is None):
            return binding
        exact = self.exact_stack_address(operand, seen)
        return exact if exact is not None and exact[1] is not None else binding


def _without_comments(text: str) -> str:
    """Blank C/C++ comments while preserving character and line positions."""

    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group())

    return re.sub(r"//[^\n]*|/\*.*?\*/", blank, text, flags=re.DOTALL)


def parse_alias_expectations(path: str | os.PathLike[str]) -> tuple[AliasExpectation, ...]:
    """Parse active alias markers without accepting commented-out checks."""

    text = Path(path).read_text(encoding="utf-8", errors="replace")
    clean = _without_comments(text)
    result = []
    for match in _MARKER_PATTERN.finditer(clean):
        result.append(
            AliasExpectation(
                match.group(1),
                clean.count("\n", 0, match.start()) + 1,
                match.group(2).strip(),
                match.group(3).strip(),
            )
        )
    return tuple(result)


def _prepare_native_cache(workspace: Path) -> None:
    """Keep pyvex's generated FFI cache inside the writable workspace."""

    cache = workspace / ".p7-work" / "native-cache"
    cache.mkdir(parents=True, exist_ok=True)
    os.environ["TEMP"] = str(cache)
    os.environ["TMP"] = str(cache)
    tempfile.tempdir = str(cache)


class _BenchmarkAnalyzer:
    def __init__(self, source: Path, binary: Path) -> None:
        self.source = source
        self.binary = binary
        _prepare_native_cache(Path(__file__).resolve().parents[3])
        self.frontend = AngrVexFrontend(binary)
        self.base = self.frontend.image.image_base
        self.segments, _ = relocated_image(binary)
        self.expectations = parse_alias_expectations(source)
        self.marker_addresses = self._marker_addresses()
        self.marker_ids = {
            address - self.base: name
            for name, address in self.marker_addresses.items()
        }
        self.lifted: dict[object, _LiftedFunction] = {}
        self.summaries: dict[object, object] = {}
        self.active_summaries: set[object] = set()
        self.diagnostics: list[str] = []

    def _symbol_address(self, name: str) -> int:
        symbol = self.frontend.project.loader.find_symbol(name)
        if symbol is None:
            raise ValueError("Binary has no required symbol " + name)
        return int(symbol.rebased_addr)

    def _marker_addresses(self) -> dict[str, int]:
        result = {}
        for marker in MARKERS:
            symbol = self.frontend.project.loader.find_symbol(marker)
            if symbol is not None:
                result[marker] = int(symbol.rebased_addr)
        if not result:
            raise ValueError("Binary has no alias marker symbols")
        return result

    def _discover_reachable(self) -> None:
        pending = [self._symbol_address("main")]
        seen: set[int] = set()
        marker_targets = set(self.marker_addresses.values())
        main_object = self.frontend.project.loader.main_object
        while pending:
            address = pending.pop()
            if address in seen or address in marker_targets:
                continue
            if len(seen) >= 256:
                raise ValueError("Reachable benchmark function limit exceeded")
            seen.add(address)
            specifications = self.frontend.discover((address,))
            result = self.frontend.lift(specifications)
            function = result.module.functions[0]
            cfg = result.cfgs()[0]
            self.lifted[function.function_id] = _LiftedFunction(
                specifications[0].name,
                function,
                cfg,
                result.module.origin_map,
                result.module.architecture,
            )
            for block in function.blocks:
                for effect in block.effects:
                    if not isinstance(effect, CallEffect) or not isinstance(
                            effect.target, DirectTarget):
                        continue
                    target = self.base + effect.target.function.rva
                    if target in marker_targets:
                        continue
                    if main_object.min_addr <= target <= main_object.max_addr:
                        pending.append(target)

    def _demand(self, item: _LiftedFunction) -> ProcedureDemand:
        function = item.function
        scope = AnalysisScope(
            function.function_id,
            ContextId(),
            "alias-benchmark",
            0,
            0,
        )
        engine = ImageMemoryEngine(
            scope,
            item.architecture,
            item.origins,
            self.segments,
            SemanticBudgets(),
            initial_policy="legacy-loader-snapshot",
            cache_resolutions=True,
        )
        port = MemoryRuntimePort(engine, cache_alias_queries=True)
        initial = legacy_entry(
            CIRAccurateDataFlow(port),
            stack_pointer=function.abi.stack_pointer or "sp",
            argument_registers=function.abi.argument_registers,
            stack_arguments=8,
            arguments_outside_frame=True,
        )
        return _AliasProcedureDemand(
            function,
            port,
            item.cfg,
            initial,
            summaries=self.summaries,
        )

    def _summary(self, function_id):
        if function_id in self.summaries:
            return self.summaries[function_id]
        if function_id in self.active_summaries:
            self.diagnostics.append(
                "Recursive summary remains conservative at " + hex(function_id.rva)
            )
            return None
        item = self.lifted.get(function_id)
        if item is None:
            return None
        self.active_summaries.add(function_id)
        for block in item.function.blocks:
            for effect in block.effects:
                if isinstance(effect, CallEffect) and isinstance(
                        effect.target, DirectTarget):
                    self._summary(effect.target.function)
        demand = self._demand(item)
        returns = []
        stores = []
        for block in item.function.blocks:
            for effect in block.effects:
                if isinstance(effect, ReturnEffect):
                    for value in effect.values:
                        returns.extend(demand.value(value))
                elif isinstance(effect, StoreEffect):
                    if demand.exact_stack_address(effect.address) is not None:
                        continue
                    stores.append(
                        (
                            effect,
                            demand.value(effect.address),
                            demand.value(effect.value),
                        )
                    )
        recipe = compile_recipe(
            demand,
            tuple(returns),
            stores=tuple(stores),
            provenance=("alias-benchmark", item.name),
        )
        self.summaries[function_id] = recipe
        self.active_summaries.remove(function_id)
        return recipe

    def _classify(self, demand, call: CallEffect):
        left_values = demand.value(call.arguments[0])
        right_values = demand.value(call.arguments[1])
        left = tuple(demand.address_binding(value) for value in left_values)
        right = tuple(demand.address_binding(value) for value in right_values)
        complete = all(binding is not None for binding in left + right)
        kinds = []
        evidence = []
        engine = demand.port.engine
        for left_binding in left:
            for right_binding in right:
                if left_binding is None or right_binding is None:
                    continue
                left_location = engine.location(
                    *left_binding,
                    engine.architecture.pointer_bits,
                    engine.architecture.endian,
                    call.origin,
                )
                right_location = engine.location(
                    *right_binding,
                    engine.architecture.pointer_bits,
                    engine.architecture.endian,
                    call.origin,
                )
                alias = demand.port.alias(
                    demand.initial.memory, left_location, right_location
                )
                kinds.append(alias.kind)
                evidence.extend(alias.evidence or alias.assessment.precision_loss)
        if complete and kinds and all(kind == AliasKind.NO for kind in kinds):
            predicted = "NOALIAS"
        elif (
                complete
                and len(left) == len(right) == len(kinds) == 1
                and kinds[0] == AliasKind.MUST):
            predicted = "MUSTALIAS"
        else:
            predicted = "MAYALIAS"
            if not complete:
                evidence.append("At least one pointer target is unresolved")
            elif not kinds:
                evidence.append("No exact location pair was available")
            else:
                evidence.append("Target alternatives are not uniformly NO or uniquely MUST")
        return predicted, tuple(kind.value for kind in kinds), tuple(dict.fromkeys(evidence)), complete

    def run(self) -> AliasBenchmarkReport:
        self._discover_reachable()
        for function_id in tuple(self.lifted):
            self._summary(function_id)
        expected_by_kind = {
            marker: [item for item in self.expectations if item.kind == marker]
            for marker in MARKERS
        }
        expected_indexes = {marker: 0 for marker in MARKERS}
        observations = []
        ordered = sorted(
            self.lifted.values(),
            key=lambda item: item.function.function_id.rva,
        )
        for item in ordered:
            demand = self._demand(item)
            calls = sorted(
                (
                    effect
                    for block in item.function.blocks
                    for effect in block.effects
                    if isinstance(effect, CallEffect)
                    and isinstance(effect.target, DirectTarget)
                    and effect.target.function.rva in self.marker_ids
                ),
                key=lambda effect: (
                    effect.site.point.instruction_rva
                    if effect.site.point.instruction_rva is not None else -1,
                    effect.site.ordinal,
                ),
            )
            for call in calls:
                marker = self.marker_ids[call.target.function.rva]
                index = expected_indexes[marker]
                candidates = expected_by_kind[marker]
                expected = candidates[index] if index < len(candidates) else None
                expected_indexes[marker] += 1
                predicted, kinds, evidence, complete = self._classify(demand, call)
                site_rva = call.site.point.instruction_rva or 0
                observations.append(
                    AliasObservation(
                        item.name,
                        self.base + site_rva,
                        marker,
                        predicted,
                        expected.kind if expected else None,
                        expected.line if expected else None,
                        expected.left if expected else None,
                        expected.right if expected else None,
                        kinds,
                        evidence,
                        complete,
                    )
                )
        missing = len(self.expectations) - len(observations)
        if missing:
            self.diagnostics.append(
                str(missing) + " source marker(s) were not matched to binary calls"
            )
        module = next(iter(self.lifted.values())).function
        return AliasBenchmarkReport(
            str(self.source.resolve()),
            str(self.binary.resolve()),
            module.function_id.binary.sha256,
            self.base,
            tuple(item.name for item in ordered),
            self.expectations,
            tuple(observations),
            tuple(self.diagnostics),
        )


def analyze_alias_benchmark(
        source: str | os.PathLike[str],
        binary: str | os.PathLike[str]) -> AliasBenchmarkReport:
    """Analyze one source/binary benchmark pair and return all marker results."""

    source_path = Path(source).resolve()
    binary_path = Path(binary).resolve()
    if not source_path.is_file() or not binary_path.is_file():
        raise FileNotFoundError("Alias benchmark source and binary must exist")
    return _BenchmarkAnalyzer(source_path, binary_path).run()
