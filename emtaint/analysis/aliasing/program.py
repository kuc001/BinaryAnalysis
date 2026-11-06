"""Native binary alias analysis over CIR, demand and MemoryQueryPort."""

from dataclasses import dataclass, replace
import os
from pathlib import Path
import tempfile

from emtaint.analysis.aliasing.demand import AliasProcedureDemand
from emtaint.analysis.aliasing.query import (
    classify_alias_operands, classify_alias_values,
)
from emtaint.analysis.taint.demand import ProcedureDemand
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.dataflow.legacy_demand import ArgumentRead, DemandLimit
from emtaint.analysis.framework.summaries import (
    ProcedureRecipe, SummaryNode, compile_recipe,
)
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.core import ContextId
from emtaint.core.contracts import (
    AnalysisScope, Constant, SemanticBudgets, ValueType,
)
from emtaint.frontends.angr_vex import AngrVexFrontend
from emtaint.frontends.loader_image import relocated_image
from emtaint.frontends.inputs import InputError
from emtaint.ir.canonical import (
    CallEffect, DirectTarget, HavocEffect, IndirectTarget, ReturnEffect,
    ReadRegister, StoreEffect, UnknownEffect, WriteRegister,
)
from emtaint.memory.image import ImageMemoryEngine
from emtaint.memory.policies import BudgetExceeded


@dataclass(frozen=True)
class _LiftedFunction:
    name: str
    function: object
    cfg: object
    origins: tuple
    architecture: object


def _prepare_native_cache(workspace: Path) -> None:
    """Keep pyvex's generated FFI cache inside the writable workspace."""

    cache = workspace / ".p7-work" / "native-cache"
    cache.mkdir(parents=True, exist_ok=True)
    os.environ["TEMP"] = str(cache)
    os.environ["TMP"] = str(cache)
    tempfile.tempdir = str(cache)


class NativeAliasProgram:
    """Lift a native binary and answer queries with shared demand and memory facts."""

    def __init__(
            self, binary: Path, observer_names: tuple[str, ...] = (),
            roots: tuple[int, ...] = ()) -> None:
        self.binary = binary
        _prepare_native_cache(Path(__file__).resolve().parents[3])
        self.frontend = AngrVexFrontend(binary)
        self.base = self.frontend.image.image_base
        self.segments, _ = relocated_image(binary)
        self.observer_names = observer_names
        self.roots = roots
        self.observer_addresses = self._observer_addresses()
        self.observer_ids = {
            address - self.base: name
            for name, address in self.observer_addresses.items()
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

    def _observer_addresses(self) -> dict[str, int]:
        result = {}
        for observer in self.observer_names:
            symbol = self.frontend.project.loader.find_symbol(observer)
            if symbol is None:
                # C++ call observers may have Itanium-mangled symbol names.
                mangled_prefix = "_Z" + str(len(observer)) + observer
                candidates = [
                    item
                    for item in self.frontend.project.loader.main_object.symbols
                    if item.is_function and item.name.startswith(mangled_prefix)
                ]
                if len(candidates) > 1:
                    raise ValueError(
                        "Binary has ambiguous C++ observer symbol " + observer
                    )
                symbol = candidates[0] if candidates else None
            if symbol is not None:
                result[observer] = int(symbol.rebased_addr)
        return result

    def _discover_reachable(self) -> None:
        main_object = self.frontend.project.loader.main_object
        observer_targets = set(self.observer_addresses.values())
        # An observer may appear in a method omitted by a direct walk from
        # the entry point. Enumerate defined functions for query discovery.
        symbols = {
            int(symbol.rebased_addr): symbol
            for symbol in main_object.symbols
            if symbol.is_function
            and not symbol.is_import
            and main_object.min_addr <= int(symbol.rebased_addr) <= main_object.max_addr
            and int(symbol.rebased_addr) not in observer_targets
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
                    "Observer call scan failed at " + hex(address)
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
            if observer_targets.intersection(direct_targets):
                selected.add(address)
        selected.update(self.roots)
        selected.add(
            self._symbol_address("main")
            if self.frontend.project.loader.find_symbol("main")
            else int(self.frontend.project.entry)
        )
        initial_specifications = {}
        try:
            initial_specifications = {
                item.address: item
                for item in self.frontend.discover(tuple(sorted(selected)))
            }
        except InputError as error:
            self.diagnostics.append(
                "Combined function discovery incomplete: " + str(error)
            )
        pending = sorted(selected, reverse=True)
        seen: set[int] = set()
        while pending:
            address = pending.pop()
            if address in seen or address in observer_targets:
                continue
            if len(seen) >= 256:
                raise ValueError("Reachable function limit exceeded")
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
                    if target in observer_targets:
                        continue
                    if main_object.min_addr <= target <= main_object.max_addr:
                        pending.append(target)

    def _demand(self, item: _LiftedFunction) -> ProcedureDemand:
        function = item.function
        scope = AnalysisScope(
            function.function_id,
            ContextId(),
            "alias-query",
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
        return AliasProcedureDemand(
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
        # Itanium ABI operator new/new[] symbols are allocation interfaces.
        # Their imported stubs have no CIR return body, so model the fresh
        # object at the shared summary boundary just like C allocators.
        allocator_names = (
            "malloc", "calloc", "_Znwm", "_Znwj", "_Znam", "_Znaj"
        )
        imported_at = self.frontend.project.loader.main_object.plt.get(item.name)
        if (
                item.name in allocator_names
                and imported_at == self.base + function_id.rva):
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
            provenance=("alias-query", item.name),
        )
        recipe = replace(
            recipe,
            stores=tuple(
                replace(
                    summary_store,
                    must_execute=self._store_must_execute(item, effect),
                    no_unknown_after=self._store_no_unknown_after(item, effect),
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
        """Treat configured observer calls as pure and retain other writes."""

        for block in item.function.blocks:
            for effect in block.effects:
                if self._unknown_write(effect):
                    return True
        return False

    def _unknown_write(self, effect) -> bool:
        if isinstance(effect, CallEffect):
            if (
                    isinstance(effect.target, DirectTarget)
                    and effect.target.function.rva in self.observer_ids):
                return False
            return bool(effect.footprint.write_regions)
        if isinstance(effect, UnknownEffect):
            return bool(effect.may_write_regions)
        return isinstance(effect, HavocEffect) and bool(effect.regions)

    def _store_no_unknown_after(self, item, store: StoreEffect) -> bool:
        """Prove no unknown write can follow this Store before normal exit.

        Any reachable later write invalidates the proof. A cycle back to an
        earlier write in the same block also invalidates it.
        """

        position = next(
            (block.id, index)
            for block in item.function.blocks
            for index, effect in enumerate(block.effects)
            if effect is store
        )
        store_block, store_index = position
        successors = {block.id: set() for block in item.function.blocks}
        for edge in item.cfg.edges:
            successors.setdefault(edge.source, set()).add(edge.target)
        later_blocks = set()
        pending = list(successors.get(store_block, ()))
        while pending:
            block_id = pending.pop()
            if block_id in later_blocks:
                continue
            later_blocks.add(block_id)
            pending.extend(successors.get(block_id, ()))
        for block in item.function.blocks:
            for index, effect in enumerate(block.effects):
                if not self._unknown_write(effect):
                    continue
                if block.id != store_block and block.id in later_blocks:
                    return False
                if block.id == store_block and (
                        index > store_index or store_block in later_blocks):
                    return False
        return True

    def _classify(self, demand, call: CallEffect):
        return classify_alias_operands(
            demand, call.arguments[0], call.arguments[1], call.origin
        )

    def _caller_contexts(self):
        """Resolve complete direct/indirect calls to lifted program bodies."""

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

    def _classify_in_callers(
            self, callee_demand, marker, contexts,
            all_contexts=None, seen=frozenset(), depth=0):
        if depth >= 8:
            raise DemandLimit(
                "Caller-context specialization depth limit",
                dimension="context-depth",
            )
        indexes = tuple(
            self._formal_index(callee_demand, operand)
            for operand in marker.arguments[:2]
        )
        local_constants = []
        for index, operand in zip(indexes, marker.arguments[:2]):
            if index is not None:
                local_constants.append(None)
                continue
            values = callee_demand.value(operand)
            concretes = {
                callee_demand.port.concrete(value) for value in values
            }
            if not values or len(concretes) != 1:
                return None
            concrete = next(iter(concretes))
            if type(concrete) is not int:
                return None
            local_constants.append(Constant(concrete, operand.type))
        results = []
        for caller_demand, caller_call in contexts:
            if any(
                    index is not None and index >= len(caller_call.arguments)
                    for index in indexes):
                return None
            arguments = list(marker.arguments)
            for position, index in enumerate(indexes):
                arguments[position] = (
                    caller_call.arguments[index]
                    if index is not None else local_constants[position]
                )
            contextual = replace(
                marker,
                origin=caller_call.origin,
                arguments=tuple(arguments),
            )
            caller_id = caller_demand.function.function_id
            outer = (all_contexts or {}).get(caller_id, ())
            nested = (
                self._classify_in_callers(
                    caller_demand, contextual, outer, all_contexts,
                    seen | {callee_demand.function.function_id}, depth + 1,
                )
                if outer and any(index is not None for index in indexes)
                and caller_id not in seen else None
            )
            results.append(
                nested if nested is not None
                else self._classify(caller_demand, contextual)
            )
        if not results:
            return None
        predictions = {result[0] for result in results}
        complete = all(result[3] for result in results)
        reasons = tuple(dict.fromkeys(
            reason for result in results for reason in result[4]
        ))
        evidence = tuple(dict.fromkeys((
            "Observation operands specialized from resolved caller targets",
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

    def query_calls(self):
        """Analyze configured binary observer calls without source expectations."""

        self._discover_reachable()
        if not any(
                isinstance(effect, CallEffect)
                and isinstance(effect.target, DirectTarget)
                and effect.target.function.rva in self.observer_ids
                for item in self.lifted.values()
                for block in item.function.blocks
                for effect in block.effects):
            return ()
        failure = None
        try:
            for function_id in tuple(self.lifted):
                self._summary(function_id)
            caller_contexts = self._caller_contexts()
        except (DemandLimit, BudgetExceeded, RecursionError) as error:
            failure = (
                "DEMAND_LIMIT" if isinstance(error, DemandLimit)
                else "BUDGET_EXCEEDED" if isinstance(error, BudgetExceeded)
                else "RECURSION_LIMIT"
            )
            self.diagnostics.append(
                "Alias query preparation incomplete: " + str(error)
            )
            caller_contexts = {}
        observations = []
        for item in sorted(
                self.lifted.values(), key=lambda entry: entry.function.function_id.rva):
            demand = self._demand(item)
            calls = sorted(
                (
                    effect for block in item.function.blocks
                    for effect in block.effects
                    if isinstance(effect, CallEffect)
                    and isinstance(effect.target, DirectTarget)
                    and effect.target.function.rva in self.observer_ids
                ),
                key=lambda effect: (
                    effect.site.point.instruction_rva
                    if effect.site.point.instruction_rva is not None else -1,
                    effect.site.ordinal,
                ),
            )
            for call in calls:
                if failure:
                    result = (
                        "INCOMPLETE", (), tuple(self.diagnostics),
                        False, (failure,),
                    )
                else:
                    try:
                        contextual = self._classify_in_callers(
                            demand, call,
                            caller_contexts.get(item.function.function_id, ()),
                            caller_contexts,
                        )
                        result = (
                            contextual if contextual is not None
                            else self._classify(demand, call)
                        )
                    except (DemandLimit, BudgetExceeded, RecursionError) as error:
                        reason = (
                            "DEMAND_LIMIT" if isinstance(error, DemandLimit)
                            else "BUDGET_EXCEEDED" if isinstance(error, BudgetExceeded)
                            else "RECURSION_LIMIT"
                        )
                        result = (
                            "INCOMPLETE", (), (str(error),), False,
                            (reason,),
                        )
                observations.append((
                    item.name,
                    self.base + (call.site.point.instruction_rva or 0),
                    self.observer_ids[call.target.function.rva],
                    *result,
                ))
        return tuple(observations)

    def query_call_arguments(
            self, function: str, site: int,
            left_index: int, right_index: int):
        """Query two argument values at one binary callsite."""

        if min(left_index, right_index) < 0:
            raise ValueError("Call argument indexes must be nonnegative")
        if not self.lifted:
            self._discover_reachable()
            for function_id in tuple(self.lifted):
                self._summary(function_id)
        item, _, _, call = self._call_at(function, site)
        if max(left_index, right_index) >= len(call.arguments):
            raise ValueError("Callsite has fewer argument values than requested")
        demand = self._demand(item)
        if left_index == 0 and right_index == 1:
            all_contexts = self._caller_contexts()
            contexts = all_contexts.get(item.function.function_id, ())
            contextual = self._classify_in_callers(
                demand, call, contexts, all_contexts,
            )
            if contextual is not None:
                return contextual
        return classify_alias_operands(
            demand, call.arguments[left_index], call.arguments[right_index],
            call.origin,
        )

    def _call_at(self, function: str, site: int):
        """Locate one exact CIR call and its effect position."""

        matches = []
        for item in self.lifted.values():
            address_name = hex(self.base + item.function.function_id.rva)
            if item.name != function and address_name != function:
                continue
            for block in item.function.blocks:
                for index, effect in enumerate(block.effects):
                    if not isinstance(effect, CallEffect):
                        continue
                    address = self.base + (effect.site.point.instruction_rva or 0)
                    if address == site:
                        matches.append((item, block, index, effect))
        if len(matches) != 1:
            raise ValueError(
                "Callsite/function does not identify one CIR call: " + hex(site)
            )
        return matches[0]

    @staticmethod
    def _locator_values(demand, item, block, index, call, locator: str):
        """Resolve a call argument, register, pointer slot or pointer literal."""

        kind, separator, value = locator.partition(":")
        if not separator or not value:
            raise ValueError("VARIABLE_MAPPING_UNAVAILABLE: invalid value locator")
        bits = item.architecture.pointer_bits
        if kind == "arg" and value.isdecimal():
            position = int(value)
            if position >= len(call.arguments):
                raise ValueError("Callsite has fewer arguments than requested")
            return demand.value(call.arguments[position])
        if kind == "reg" and value.isidentifier():
            registers = {
                effect.source.register
                for source in item.function.blocks
                for effect in source.effects
                if isinstance(effect, ReadRegister)
            } | {
                effect.target.register
                for source in item.function.blocks
                for effect in source.effects
                if isinstance(effect, WriteRegister)
            }
            if value not in registers:
                raise ValueError(
                    "VARIABLE_MAPPING_UNAVAILABLE: register is absent from CIR"
                )
            return demand.register(block.id, index, value, bits, 0)
        if kind in ("mem", "addr"):
            try:
                absolute = int(value, 0)
            except ValueError as error:
                raise ValueError(
                    "VARIABLE_MAPPING_UNAVAILABLE: invalid absolute address"
                ) from error
            if not 0 <= absolute < 1 << bits:
                raise ValueError("Pointer address is outside architecture width")
            pointer = demand.port.constant(
                absolute, ValueType.pointer(bits), call.origin,
            )
            if kind == "addr":
                return (pointer,)
            query = ArgumentRead(
                bits, item.architecture.endian, call.origin,
            )
            return demand.read(block.id, index, pointer, query, 0)
        raise ValueError(
            "VARIABLE_MAPPING_UNAVAILABLE: use arg:N, reg:NAME, "
            "mem:ADDRESS or addr:ADDRESS"
        )

    def query_call_locators(
            self, function: str, site: int, left: str, right: str):
        """Query two pointer values at one callsite using explicit locators."""

        if left.startswith("arg:") and right.startswith("arg:"):
            if not left[4:].isdecimal() or not right[4:].isdecimal():
                raise ValueError(
                    "VARIABLE_MAPPING_UNAVAILABLE: invalid argument locator"
                )
            return self.query_call_arguments(
                function, site, int(left[4:]), int(right[4:]),
            )
        if not self.lifted:
            self._discover_reachable()
            for function_id in tuple(self.lifted):
                self._summary(function_id)
        item, block, index, call = self._call_at(function, site)
        demand = self._demand(item)
        left_values = self._locator_values(
            demand, item, block, index, call, left,
        )
        right_values = self._locator_values(
            demand, item, block, index, call, right,
        )
        return classify_alias_values(
            demand, left_values, right_values, call.origin,
        )
