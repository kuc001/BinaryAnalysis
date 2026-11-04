"""Run source-annotated alias checks against a native benchmark binary.

The source markers are expectations, never analysis inputs.  Marker calls in
the binary provide only the two queried pointer values and the observation
site.  Values are reconstructed backwards with ``ProcedureDemand``; direct
callee stores are exported as detached recipes and instantiated at the caller
so a strong update such as ``*k = *s`` can affect the later query.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import os
from pathlib import Path
import re
import tempfile

from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.framework.summaries import (
    ProcedureRecipe,
    SummaryNode,
    compile_recipe,
)
from emtaint.analysis.taint.demand import ProcedureDemand
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.core import ContextId
from emtaint.core import Completeness
from emtaint.core.contracts import (
    AnalysisScope,
    Constant,
    SemanticBudgets,
    ValueType,
)
from emtaint.frontends.angr_vex import AngrVexFrontend
from emtaint.frontends.loader_image import relocated_image
from emtaint.frontends.inputs import InputError
from emtaint.ir.canonical import (
    CallEffect,
    Compute,
    DirectTarget,
    HavocEffect,
    IndirectTarget,
    ReturnEffect,
    StoreEffect,
    UnknownEffect,
)
from emtaint.memory import AliasKind, SymbolicOp
from emtaint.memory.image import ImageMemoryEngine


MARKERS = (
    "NOALIAS",
    "MAYALIAS",
    "MUSTALIAS",
    "PARTIALALIAS",
    "EXPECTEDFAIL_MAYALIAS",
    "EXPECTEDFAIL_NOALIAS",
)
_MARKER_PATTERN = re.compile(
    r"\b(" + "|".join(MARKERS) + r")\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)"
)

_EXPECTED_KIND = {
    "EXPECTEDFAIL_MAYALIAS": "MAYALIAS",
    "EXPECTEDFAIL_NOALIAS": "NOALIAS",
}


@dataclass(frozen=True)
class AliasExpectation:
    """One active source marker and its human-readable operands."""

    kind: str
    line: int
    left: str
    right: str
    status: str = "required"
    marker: str | None = None

    def __post_init__(self) -> None:
        marker = self.kind if self.marker is None else self.marker
        if marker not in MARKERS:
            raise ValueError("Unsupported alias expectation marker " + marker)
        if self.status not in ("required", "xfail"):
            raise ValueError("Unsupported alias expectation status " + self.status)
        object.__setattr__(self, "marker", marker)


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
    reason_codes: tuple[str, ...] = ()
    expected_status: str = "required"

    @property
    def matched(self) -> bool | None:
        """Return expectation agreement, or None without a source marker."""

        return (
            None
            if self.expected is None
            else self.complete and self.predicted == self.expected
        )


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
        return sum(
            item.expected_status == "required" and item.matched is True
            for item in self.observations
        )

    @property
    def total(self) -> int:
        return sum(item.status == "required" for item in self.expectations)

    @property
    def xfailed(self) -> int:
        """Return expected-failure checks that still disagree or are incomplete."""

        return sum(
            item.expected_status == "xfail" and item.matched is False
            for item in self.observations
        )

    @property
    def xpassed(self) -> int:
        """Return expected-failure checks now satisfied by the analyzer."""

        return sum(
            item.expected_status == "xfail" and item.matched is True
            for item in self.observations
        )

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
            "xfailed": self.xfailed,
            "xpassed": self.xpassed,
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

    def value(self, operand, depth=0):
        definition = self.defs.get(operand.id) if hasattr(operand, "id") else None
        if definition and isinstance(definition[2], CallEffect):
            call = definition[2]
            summary = (
                self.summaries.get(call.target.function)
                if isinstance(call.target, DirectTarget) else None
            )
            if summary is not None and summary.returns:
                return summary.instantiate(self, call, depth + 1)
        return super().value(operand, depth)

    def _constant_image_address(self, operand, seen=frozenset()):
        """Fold a pure CIR address before selecting its image segment."""

        if isinstance(operand, Constant):
            return operand.value if type(operand.value) is int else None
        if operand.id in seen or operand.id not in self.defs:
            return None
        effect = self.defs[operand.id][2]
        if not isinstance(effect, Compute):
            return None
        next_seen = seen | {operand.id}
        if effect.op.value == "copy":
            return self._constant_image_address(effect.args[0], next_seen)
        if effect.op.value not in ("add", "sub"):
            return None
        left = self._constant_image_address(effect.args[0], next_seen)
        right = self._constant_image_address(effect.args[1], next_seen)
        if type(left) is not int or type(right) is not int:
            return None
        value = left + right if effect.op.value == "add" else left - right
        return value % (1 << self.port.engine.architecture.pointer_bits)

    def local_address(self, operand, seen=frozenset()):
        absolute = self._constant_image_address(operand, seen)
        if type(absolute) is int:
            image = self.port.engine.address(absolute)
            if image is not None:
                return image
        binding = super().local_address(operand, seen)
        if binding is not None and not (
                binding[0].region == "stack" and binding[1] is None):
            return binding
        exact = self.exact_stack_address(operand, seen)
        if exact is not None and exact[1] is not None:
            return exact
        if not hasattr(operand, "id"):
            return binding
        active = getattr(self, "_local_address_demands", set())
        if operand.id in active:
            return binding
        self._local_address_demands = active
        active.add(operand.id)
        try:
            alternatives = self.value(operand)
            resolved = tuple(
                self.address_binding(reference) for reference in alternatives
            )
        finally:
            active.remove(operand.id)
        if resolved and all(
                candidate is not None and candidate == resolved[0]
                for candidate in resolved):
            return resolved[0]
        return binding

    def address_binding(self, reference, seen=frozenset()):
        allocation = getattr(self, "allocation_bindings", {}).get(reference)
        if allocation is not None:
            return allocation
        binding = super().address_binding(reference, seen)
        if binding is not None:
            return binding
        proof = self.address_normalizer.indexed_stack_address(reference)
        return None if proof is None else proof.binding

    def read(self, block, index, address, effect, depth):
        """Keep the empty element alternative for an indexed stack load."""

        proof = self.address_normalizer.indexed_stack_address(address)
        result = super().read(block, index, address, effect, depth)
        if proof is None:
            return result
        port = self.port
        engine = port.engine
        location = engine.location(
            *proof.binding, effect.width_bits, effect.endian, effect.origin
        )
        location = port.addressed_location(location, address)
        initial = port.read(
            self.initial.memory,
            location,
            port.constant(True, ValueType.boolean(), effect.origin),
            effect.origin,
        ).value
        self.loads[initial] = (
            address, effect.width_bits, effect.endian, effect.origin
        )
        return self.union((result, (initial,)))

    def uninitialized_frame_pointer(self, reference, seen=frozenset()):
        """Recognize an unwritten pointer slot in this function's frame.

        The alias benchmark follows the underlying points-to convention that
        an uninitialized local pointer contributes an empty target
        alternative.  This is deliberately narrower than Unknown: only an
        exact negative stack-frame read from the entry memory qualifies.
        """

        if reference in seen:
            return False
        seen = seen | {reference}
        engine = self.port.engine
        node = engine.dag.nodes[reference]
        if node.op == SymbolicOp.COPY:
            return self.uninitialized_frame_pointer(node.operands[0], seen)
        if node.op != SymbolicOp.MEMORY_READ or node.state != self.initial.memory:
            return False
        location = engine.locations.get(node.location)
        if (
                location is None
                or location.object_id is None
                or location.offset_lower is None
                or location.offset_lower != location.offset_upper):
            return False
        root = engine.roots.get(location.object_id)
        if root is None or root.region != "stack":
            return False
        modulus = 1 << engine.architecture.pointer_bits
        signed_offset = (
            (location.offset_lower + modulus // 2) % modulus
            - modulus // 2
        )
        return signed_offset < 0


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
        marker = match.group(1)
        result.append(
            AliasExpectation(
                _EXPECTED_KIND.get(marker, marker),
                clean.count("\n", 0, match.start()) + 1,
                match.group(2).strip(),
                match.group(3).strip(),
                "xfail" if marker.startswith("EXPECTEDFAIL_") else "required",
                marker,
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
            if symbol is None:
                # The header is compiled as C++ in basic_cpp_tests, so the
                # same marker has an Itanium length-prefixed symbol name.
                mangled_prefix = "_Z" + str(len(marker)) + marker
                candidates = [
                    item
                    for item in self.frontend.project.loader.main_object.symbols
                    if item.is_function and item.name.startswith(mangled_prefix)
                ]
                if len(candidates) > 1:
                    raise ValueError(
                        "Binary has ambiguous C++ alias marker " + marker
                    )
                symbol = candidates[0] if candidates else None
            if symbol is not None:
                result[marker] = int(symbol.rebased_addr)
        if not result:
            raise ValueError("Binary has no alias marker symbols")
        return result

    def _discover_reachable(self) -> None:
        main_object = self.frontend.project.loader.main_object
        marker_targets = set(self.marker_addresses.values())
        # SVF-style source markers are whole-module assertions, including
        # assertions in virtual methods that a direct-call walk from main
        # cannot reach.  Enumerating defined function symbols is benchmark
        # scope discovery, not an alternative production call graph.
        symbols = {
            int(symbol.rebased_addr): symbol
            for symbol in main_object.symbols
            if symbol.is_function
            and not symbol.is_import
            and main_object.min_addr <= int(symbol.rebased_addr) <= main_object.max_addr
            and int(symbol.rebased_addr) not in marker_targets
            and int(symbol.size) > 0
        }
        selected = set()
        for address, symbol in symbols.items():
            try:
                block = self.frontend.project.factory.block(
                    address,
                    size=int(symbol.size),
                    opt_level=0,
                    cross_insn_opt=False,
                )
            except (ValueError, TypeError) as error:
                self.diagnostics.append(
                    "Benchmark marker scan failed at " + hex(address)
                    + ": " + str(error)
                )
                continue
            direct_targets = {
                int(operand.imm)
                for instruction in block.capstone.insns
                if instruction.insn.mnemonic.startswith(("call", "bl"))
                and instruction.insn.operands
                for operand in instruction.insn.operands[:1]
                if operand.type == 2
            }
            if marker_targets.intersection(direct_targets):
                selected.add(address)
        selected.add(self._symbol_address("main"))
        initial_specifications = {}
        try:
            initial_specifications = {
                item.address: item
                for item in self.frontend.discover(tuple(sorted(selected)))
            }
        except InputError as error:
            self.diagnostics.append(
                "Combined benchmark discovery incomplete: " + str(error)
            )
        pending = sorted(selected, reverse=True)
        seen: set[int] = set()
        while pending:
            address = pending.pop()
            if address in seen or address in marker_targets:
                continue
            if len(seen) >= 256:
                raise ValueError("Reachable benchmark function limit exceeded")
            seen.add(address)
            try:
                specification = initial_specifications.get(address)
                specifications = (
                    (specification,)
                    if specification is not None
                    else self.frontend.discover((address,))
                )
            except InputError as error:
                self.diagnostics.append(
                    "Benchmark function discovery incomplete at "
                    + hex(address) + ": " + str(error)
                )
                continue
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
        if item.name in ("malloc", "calloc"):
            origin = item.origins[0].id
            recipe = ProcedureRecipe(
                function_id,
                (SummaryNode(
                    ValueType.bv(item.architecture.pointer_bits),
                    "allocation",
                    origin=origin,
                ),),
                (0,),
                (),
                (),
                ("modeled-allocator", item.name),
                (),
                False,
            )
            self.summaries[function_id] = recipe
            return recipe
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
                    local = demand.address_normalizer.exact_stack_address(
                        effect.address
                    )
                    if local is not None and local.root.region == "stack":
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
        recipe = replace(
            recipe,
            stores=tuple(
                replace(
                    summary_store,
                    must_execute=self._store_must_execute(item, effect),
                )
                for summary_store, (effect, _, _) in zip(
                    recipe.stores, stores
                )
            ),
            unknown_effects=self._summary_has_unknown_effects(item),
        )
        self.summaries[function_id] = recipe
        self.active_summaries.remove(function_id)
        return recipe

    def _store_must_execute(self, item, effect: StoreEffect) -> bool:
        """Prove that a true-guarded Store dominates every normal return."""

        if getattr(effect.guard, "value", None) is not True:
            return False
        positions = {
            candidate: (block.id, index)
            for block in item.function.blocks
            for index, candidate in enumerate(block.effects)
        }
        store_block, store_index = positions[effect]
        successors = {block.id: set() for block in item.function.blocks}
        predecessors = {block.id: set() for block in item.function.blocks}
        for edge in item.cfg.edges:
            successors.setdefault(edge.source, set()).add(edge.target)
            predecessors.setdefault(edge.target, set()).add(edge.source)
        reachable = set()
        todo = [item.cfg.entry]
        while todo:
            block = todo.pop()
            if block in reachable:
                continue
            reachable.add(block)
            todo.extend(successors.get(block, ()))
        returns = [
            (block.id, index)
            for block in item.function.blocks
            for index, candidate in enumerate(block.effects)
            if isinstance(candidate, ReturnEffect) and block.id in reachable
        ]
        if not returns or store_block not in reachable:
            return False
        dominators = {
            block: ({block} if block == item.cfg.entry else set(reachable))
            for block in reachable
        }
        changed = True
        while changed:
            changed = False
            for block in reachable - {item.cfg.entry}:
                incoming = predecessors.get(block, set()) & reachable
                updated = {block}
                if incoming:
                    updated.update(set.intersection(*(
                        dominators[parent] for parent in incoming
                    )))
                if updated != dominators[block]:
                    dominators[block] = updated
                    changed = True
        return all(
            store_block in dominators[return_block]
            and (store_block != return_block or store_index < return_index)
            for return_block, return_index in returns
        )

    def _summary_has_unknown_effects(self, item) -> bool:
        """Ignore benchmark observations, but retain real unknown writes."""

        for block in item.function.blocks:
            for effect in block.effects:
                if isinstance(effect, CallEffect):
                    if (
                            isinstance(effect.target, DirectTarget)
                            and effect.target.function.rva in self.marker_ids):
                        continue
                    if effect.footprint.write_regions:
                        return True
                elif isinstance(effect, UnknownEffect):
                    if effect.may_write_regions:
                        return True
                elif isinstance(effect, HavocEffect) and effect.regions:
                    return True
        return False

    def _classify(self, demand, call: CallEffect):
        left_values = demand.value(call.arguments[0])
        right_values = demand.value(call.arguments[1])
        left_indexed = tuple(
            value for value in left_values
            if demand.address_normalizer.indexed_stack_address(value) is not None
        )
        right_indexed = tuple(
            value for value in right_values
            if demand.address_normalizer.indexed_stack_address(value) is not None
        )
        left_empty = tuple(
            value for value in left_values
            if demand.uninitialized_frame_pointer(value)
        )
        right_empty = tuple(
            value for value in right_values
            if demand.uninitialized_frame_pointer(value)
        )
        left = tuple(
            demand.address_binding(value) for value in left_values
            if value not in left_empty
        )
        right = tuple(
            demand.address_binding(value) for value in right_values
            if value not in right_empty
        )
        reasons = []
        if (not left and not left_empty) or (not right and not right_empty):
            reasons.append("NO_LOCATION_ALTERNATIVES")
        if any(binding is None for binding in left + right):
            reasons.append("ADDRESS_UNRESOLVED")
        if any(
                binding is not None and binding[1] is None
                for binding in left + right):
            reasons.append("OFFSET_UNRESOLVED")
        kinds = []
        evidence = []
        left_locations = []
        right_locations = []
        engine = demand.port.engine
        # Marker operands are pointer values.  Their alias relation concerns
        # the addressed byte identity, not an implicit pointer-sized memory
        # access starting at each address.  Actual Load/Store effects retain
        # their CIR widths elsewhere in the demand and memory engines.
        address_identity_width = 8
        for binding in left:
            if binding is not None:
                left_locations.append(engine.location(
                    *binding, address_identity_width,
                    engine.architecture.endian, call.origin))
        for binding in right:
            if binding is not None:
                right_locations.append(engine.location(
                    *binding, address_identity_width,
                    engine.architecture.endian, call.origin))
        if any(
                location.assessment.status != Completeness.COMPLETE
                for location in left_locations + right_locations):
            reasons.append("LOCATION_INCOMPLETE")
        for left_location in left_locations:
            for right_location in right_locations:
                alias = demand.port.alias(
                    demand.initial.memory, left_location, right_location
                )
                kinds.append(alias.kind)
                evidence.extend(alias.evidence or alias.assessment.precision_loss)
                if alias.assessment.status != Completeness.COMPLETE:
                    reasons.append("ALIAS_INCOMPLETE")
        complete = not reasons
        canonical_left = {
            (location.object_id, location.byte_interval)
            for location in left_locations
        }
        canonical_right = {
            (location.object_id, location.byte_interval)
            for location in right_locations
        }
        if left_empty or right_empty:
            evidence.append(
                "Uninitialized local pointer contributes an empty points-to alternative"
            )
        if left_indexed or right_indexed:
            evidence.append(
                "Indexed stack address retains affine stride uncertainty"
            )
        if not complete:
            predicted = "INCOMPLETE"
            evidence.append("Alias query is incomplete")
        elif not left_locations or not right_locations:
            predicted = "NOALIAS"
        elif kinds and all(kind == AliasKind.NO for kind in kinds):
            predicted = "NOALIAS"
        elif (
                len(canonical_left) == len(canonical_right) == 1
                and kinds
                and all(kind == AliasKind.MUST for kind in kinds)
                and not left_empty
                and not right_empty
                and not left_indexed
                and not right_indexed):
            predicted = "MUSTALIAS"
        else:
            predicted = "MAYALIAS"
            if not kinds:
                evidence.append("No exact location pair was available")
            else:
                evidence.append("Target alternatives are not uniformly NO or uniquely MUST")
        return (
            predicted,
            tuple(kind.value for kind in kinds),
            tuple(dict.fromkeys(evidence)),
            complete,
            tuple(dict.fromkeys(reasons)),
        )

    def _caller_contexts(self):
        """Resolve complete direct/indirect calls to lifted benchmark bodies."""

        by_rva = {
            function_id.rva: function_id for function_id in self.lifted
        }
        contexts = {function_id: [] for function_id in self.lifted}
        for item in self.lifted.values():
            demand = self._demand(item)
            for block in item.function.blocks:
                for call in block.effects:
                    if not isinstance(call, CallEffect):
                        continue
                    target = None
                    if isinstance(call.target, DirectTarget):
                        target = call.target.function
                    elif isinstance(call.target, IndirectTarget):
                        values = demand.value(call.target.address)
                        addresses = tuple(
                            demand.port.concrete(value) for value in values
                        )
                        if (
                                addresses
                                and all(type(address) is int for address in addresses)
                                and len(set(addresses)) == 1):
                            target = by_rva.get(addresses[0] - self.base)
                    if target in contexts:
                        contexts[target].append((demand, call))
        return contexts

    @staticmethod
    def _formal_index(demand, operand):
        """Return one exact formal root index, or None for any ambiguity."""

        bindings = tuple(
            demand.address_binding(value) for value in demand.value(operand)
        )
        if not bindings or any(binding is None for binding in bindings):
            return None
        indexes = {
            binding[0].object_id.coordinates[0]
            for binding in bindings
            if binding[0].region == "argument" and binding[1] == 0
        }
        if len(indexes) != 1 or len(indexes) != len({
                binding[0].object_id.coordinates[0]
                for binding in bindings}):
            return None
        index = next(iter(indexes))
        return index if type(index) is int else None

    def _classify_in_callers(self, callee_demand, marker, contexts):
        indexes = tuple(
            self._formal_index(callee_demand, operand)
            for operand in marker.arguments[:2]
        )
        if any(index is None for index in indexes):
            return None
        results = []
        for caller_demand, caller_call in contexts:
            if any(index >= len(caller_call.arguments) for index in indexes):
                return None
            arguments = list(marker.arguments)
            arguments[0] = caller_call.arguments[indexes[0]]
            arguments[1] = caller_call.arguments[indexes[1]]
            contextual = replace(
                marker,
                origin=caller_call.origin,
                arguments=tuple(arguments),
            )
            results.append(self._classify(caller_demand, contextual))
        if not results:
            return None
        predictions = {result[0] for result in results}
        complete = all(result[3] for result in results)
        reasons = tuple(dict.fromkeys(
            reason for result in results for reason in result[4]
        ))
        evidence = tuple(dict.fromkeys((
            "Marker formals specialized from complete caller target evidence",
            *(item for result in results for item in result[2]),
        )))
        if not complete:
            predicted = "INCOMPLETE"
        elif len(predictions) == 1:
            predicted = next(iter(predictions))
        else:
            predicted = "MAYALIAS"
            evidence += ("Resolved caller contexts have mixed alias relations",)
        kinds = tuple(dict.fromkeys(
            kind for result in results for kind in result[1]
        ))
        return predicted, kinds, evidence, complete, reasons

    def run(self) -> AliasBenchmarkReport:
        self._discover_reachable()
        for function_id in tuple(self.lifted):
            self._summary(function_id)
        caller_contexts = self._caller_contexts()
        expected_by_kind = {
            marker: [item for item in self.expectations if item.marker == marker]
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
                contextual = self._classify_in_callers(
                    demand,
                    call,
                    caller_contexts.get(item.function.function_id, ()),
                )
                if contextual is None:
                    contextual = self._classify(demand, call)
                predicted, kinds, evidence, complete, reasons = contextual
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
                        reasons,
                        expected.status if expected else "required",
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
