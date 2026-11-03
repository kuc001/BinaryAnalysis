"""P6 pure descriptor adapter over P5 ``MemoryQueryPort``.

Core transfers use this public value/location/query interface, not heap
internals. High-frequency operations expose sampled DEBUG events so manual
analysis can follow SSE, APG, memory and alias decisions without changing the
semantic state or flooding the log.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import replace
from itertools import product
import logging

from emtaint.core.contracts import (
    MemoryLocationId,
    MemoryVersionId,
    SymbolicExprId,
    TypeKind,
    ValueType,
    same_scope,
)
from emtaint.debugging import EventSampler, function_address_fields
from emtaint.memory import (
    AliasKind,
    ReadMemory,
    SymbolicOp,
    UpdateKind,
    WriteMemory,
)
from emtaint.memory.access_graph import AccessGraphArena
from emtaint.memory.engine import PythonMemoryEngine, token
from emtaint.memory.policies import BudgetExceeded
from emtaint.memory.query_port import (
    DefinitionResult,
    QueryBudget,
    ReadResult,
    WriteResult,
)
from emtaint.memory.state import AliasResult, MemoryLocation


LOGGER = logging.getLogger(__name__)


def _key(value: object) -> str:
    """Return a compact stable identity suitable for diagnostic fields."""

    return str(getattr(value, "token", value))


class MemoryRuntimePort:
    """Adapt the P5 memory engine to CIR transfer operations.

    Args:
        engine: Function/context-scoped image memory engine.
        budget: Per-query step, candidate, solver and timeout limits.
        cache_alias_queries: Enable the bounded alias-result cache used by the
            iCall execution path. Disabling it always delegates to the engine.
    """

    def __init__(
        self,
        engine: PythonMemoryEngine,
        budget: QueryBudget = QueryBudget(),
        *,
        cache_alias_queries: bool = False,
    ) -> None:
        self.engine = engine
        self.scope = engine.scope
        self.budget = budget
        self.initial = engine.initial
        self.seed_addresses: dict[str, tuple[object, int]] = {}
        self.calls = {
            name: 0
            for name in (
                "read",
                "write",
                "resolve_alias",
                "resolve_definition",
                "havoc",
            )
        }
        self.validate_current = lambda: None
        self._concrete_memo: dict[SymbolicExprId, int | bool] = {}
        self._alias_cache_enabled = cache_alias_queries
        self._alias_cache: dict[object, AliasResult] = {}
        self._alias_hits = 0
        self._alias_misses = 0
        self._events = EventSampler(LOGGER)
        if not hasattr(engine, "access_graph_arena"):
            engine.access_graph_arena = AccessGraphArena(
                engine.scope,
                engine.budgets,
                graphs=engine.graphs,
            )
        self.apg = engine.access_graph_arena
        self._events.emit(
            "memory.port.initialized",
            **function_address_fields(
                self.scope.function.rva,
                getattr(engine, "image_base", 0),
            ),
            context=_key(self.scope.context),
            initial_memory=_key(self.initial),
            alias_cache=cache_alias_queries,
        )

    def bind_address(self, name: str, root: object, offset: int) -> None:
        """Bind a frontend address name to an APG root and byte offset."""

        self.seed_addresses[name] = (root, offset)
        self._events.emit(
            "apg.address.bound",
            name=name,
            root=_key(root),
            offset=offset,
        )

    def constant(
        self,
        value: int | bool,
        type_: ValueType,
        origin: str,
    ) -> SymbolicExprId:
        """Create or intern a typed SSE constant leaf."""

        self.validate_current()
        result = self.engine.dag.make(
            type_,
            SymbolicOp.CONSTANT,
            origin=origin,
            value=value,
        )
        self._events.emit(
            "sse.constant.created",
            expression=_key(result),
            value=value,
            type=str(type_),
            origin=origin,
        )
        return result

    def symbol(
        self,
        name: str,
        type_: ValueType,
        origin: str,
    ) -> SymbolicExprId:
        """Create or intern a named typed SSE input leaf."""

        self.validate_current()
        result = self.engine.dag.symbol(name, type_, origin)
        self._events.emit(
            "sse.symbol.created",
            expression=_key(result),
            name=name,
            type=str(type_),
            origin=origin,
        )
        return result

    def unknown(
        self,
        type_: ValueType,
        origin: str,
        reason: str,
    ) -> SymbolicExprId:
        """Create an explicit SSE unknown leaf with its precision reason."""

        self.validate_current()
        result = self.engine.dag.make(
            type_,
            SymbolicOp.UNKNOWN,
            origin=origin,
            value=reason,
        )
        self._events.emit(
            "sse.unknown.created",
            expression=_key(result),
            type=str(type_),
            origin=origin,
            reason=reason,
        )
        return result

    def operation(
        self,
        op: object,
        type_: ValueType,
        args: Sequence[SymbolicExprId],
        origin: str,
        params: Sequence[int] = (),
    ) -> SymbolicExprId:
        """Create or intern a pure typed SSE operation node."""

        self.validate_current()
        operation = SymbolicOp(op.value if hasattr(op, "value") else op)
        result = self.engine.dag.operation(
            operation,
            type_,
            args,
            origin,
            params,
        )
        self._events.emit(
            "sse.operation.created",
            expression=_key(result),
            operation=operation.value,
            operands=[_key(arg) for arg in args],
            type=str(type_),
            origin=origin,
            params=list(params),
        )
        return result

    def type_of(self, reference: SymbolicExprId) -> ValueType:
        """Return the static value type of an SSE expression."""

        return self.engine.dag.nodes[reference].type

    def concrete(self, reference: SymbolicExprId) -> int | bool | None:
        """Evaluate an SSE expression only when its value is proven constant."""

        self.validate_current()
        literal = self.engine.dag.constant_value(reference)
        if literal is not None:
            return literal
        node = self.engine.dag.nodes[reference]
        if node.op in (SymbolicOp.SYMBOL, SymbolicOp.UNKNOWN):
            return None
        if reference in self._concrete_memo:
            return self._concrete_memo[reference]
        value = self.engine.constant_value(reference)
        # Only proven constants are cached. An unresolved read may later be
        # refined by new object/alias evidence; every read ID includes its
        # immutable memory version, and a stale port still fails above.
        if value is not None:
            self._concrete_memo[reference] = value
        self._events.emit(
            "sse.constant_evaluation.completed",
            expression=_key(reference),
            resolved=value is not None,
            value=value,
        )
        return value

    def guard_concrete(self, reference: SymbolicExprId) -> int | bool | None:
        """Evaluate a guard with the engine's runtime-aware constant policy."""

        self.validate_current()
        literal = self.engine.dag.constant_value(reference)
        if literal is not None:
            return literal
        evaluate = getattr(
            self.engine,
            "runtime_constant_value",
            self.engine.constant_value,
        )
        value = evaluate(reference)
        self._events.emit(
            "sse.guard_evaluation.completed",
            expression=_key(reference),
            resolved=value is not None,
            value=value,
        )
        return value

    def point(self, origin: str) -> object:
        """Resolve an origin ID to its CIR program point."""

        return self.engine.origin_record(origin).point

    def location(
        self,
        operand: object,
        bindings: Mapping[object, tuple[object, int]],
        values: Mapping[object, SymbolicExprId],
        width: int,
        endian: object,
        origin: str,
    ) -> MemoryLocation:
        """Resolve a CIR address operand into an abstract memory location.

        ``bindings`` carries proven APG root/offset pairs. If no binding is
        available, concrete address evidence is queried from ``values``. A
        remaining symbolic address becomes an addressed unknown location so
        nested loads retain distinct identities.
        """

        self.validate_current()
        operand_id = getattr(operand, "id", None)
        binding = bindings.get(operand_id) if operand_id is not None else None
        if binding is None:
            if hasattr(operand, "value"):
                value = operand.value
            elif operand_id in values:
                value = self.concrete(values[operand_id])
            else:
                value = None
            if type(value) is int and hasattr(self.engine, "address"):
                binding = self.engine.address(value)
        if binding is None:
            location = self.engine.location(None, None, width, endian, origin)
            address = values.get(operand_id, operand) if operand_id is not None else operand
            result = self.addressed_location(location, address)
            self._events.emit(
                "memory.location.unknown",
                location=_key(result.id),
                address=_key(address),
                width_bits=width,
                endian=str(endian),
                origin=origin,
            )
            return result
        root, offset = binding
        result = self.engine.location(
            root,
            offset % (1 << self.engine.architecture.pointer_bits),
            width,
            endian,
            origin,
        )
        self._events.emit(
            "memory.location.resolved",
            location=_key(result.id),
            object_id=_key(result.object_id),
            offset=result.offset_lower,
            width_bits=width,
            endian=str(endian),
            origin=origin,
        )
        return result

    def addressed_location(
        self,
        location: MemoryLocation,
        address: object,
    ) -> MemoryLocation:
        """Keep unknown read identities separate without asserting no-alias.

        Two different address demands at the same native origin can share an
        unknown location descriptor. They cannot share one deferred-read leaf:
        that would collapse nested loads and lose the address dependency.
        """

        self.validate_current()
        replaced = replace(
            location,
            id=MemoryLocationId(
                self.scope,
                "addressed-" + token((location.id, address)),
            ),
        )
        result = self.engine._register_location(replaced)
        self._events.emit(
            "memory.location.addressed",
            base_location=_key(location.id),
            location=_key(result.id),
            address=_key(address),
        )
        return result

    def read(
        self,
        state: MemoryVersionId,
        location: MemoryLocation,
        guard: SymbolicExprId | None,
        origin: str,
    ) -> ReadResult:
        """Create and register a versioned memory-read SSE leaf."""

        self.validate_current()
        self.calls["read"] += 1
        placeholder = self.engine.dag.make(
            ValueType.bv(location.width_bits),
            SymbolicOp.MEMORY_READ,
            origin=origin,
            state=state,
            location=location.id,
        )
        result = self.engine.read(
            ReadMemory(state, location.id, placeholder, guard, origin),
            self.budget,
        )
        self._events.emit(
            "memory.read.completed",
            state=_key(state),
            location=_key(location.id),
            object_id=_key(location.object_id),
            offset_lower=location.offset_lower,
            offset_upper=location.offset_upper,
            width_bits=location.width_bits,
            guard=_key(guard),
            result=_key(result.value),
            result_state=_key(result.state),
            completeness=result.assessment.status.value,
            precision=result.assessment.precision.value,
            origin=origin,
        )
        return result

    def write(
        self,
        state: MemoryVersionId,
        location: MemoryLocation,
        value: SymbolicExprId,
        guard: SymbolicExprId | None,
        origin: str,
    ) -> WriteResult:
        """Apply a strong or weak versioned write from proven alias evidence."""

        self.validate_current()
        self.calls["write"] += 1
        self.calls["resolve_alias"] += 1
        alias = self.engine.resolve_alias(
            state,
            location,
            location,
            self.budget,
        )
        strong = alias.kind == AliasKind.MUST
        request = WriteMemory(
            state,
            location.id,
            value,
            guard,
            UpdateKind.STRONG if strong else UpdateKind.WEAK,
            alias,
            origin,
            strong,
            strong,
        )
        result = self.engine.write(request, self.budget)
        self._events.emit(
            "memory.write.completed",
            parent_state=_key(state),
            state=_key(result.state),
            location=_key(location.id),
            value=_key(value),
            guard=_key(guard),
            update=request.update.value,
            alias=alias.kind.value,
            origin=origin,
            completeness=result.assessment.status.value,
            precision=result.assessment.precision.value,
        )
        return result

    def alias(
        self,
        state: MemoryVersionId,
        left: MemoryLocation,
        right: MemoryLocation,
    ) -> AliasResult:
        """Resolve aliasing, optionally reusing a bounded evidence-keyed cache."""

        self.validate_current()
        self.calls["resolve_alias"] += 1
        engine = self.engine
        if not self._alias_cache_enabled:
            result = engine.resolve_alias(state, left, right, self.budget)
            self._log_alias("alias.query.completed", state, left, right, result)
            return result
        if state not in engine.versions:
            raise ValueError("Unknown memory version")
        same_scope(self.scope, left.id, right.id)
        if left.object_id is None or right.object_id is None:
            cache_key = (state, "unknown-object")
        else:
            if left.object_id not in engine.objects or right.object_id not in engine.objects:
                raise ValueError("Unregistered alias operand")
            cache_key = (
                state,
                left.object_id,
                right.object_id,
                left.offset_lower,
                left.offset_upper,
                right.offset_lower,
                right.offset_upper,
                left.width_bits,
                right.width_bits,
                left.endian,
                right.endian,
                left.address_space,
                right.address_space,
                engine.object_facts.get(left.object_id),
                engine.object_facts.get(right.object_id),
            )
        if cache_key in self._alias_cache:
            self._alias_hits += 1
            result = self._alias_cache[cache_key]
            self._log_alias("alias.cache.hit", state, left, right, result)
            return result
        self._alias_misses += 1
        result = engine.resolve_alias(state, left, right, self.budget)
        if len(self._alias_cache) < 8_192:
            self._alias_cache[cache_key] = result
        self._log_alias("alias.cache.miss", state, left, right, result)
        return result

    def _log_alias(
        self,
        event: str,
        state: MemoryVersionId,
        left: MemoryLocation,
        right: MemoryLocation,
        result: AliasResult,
    ) -> None:
        """Emit one sampled alias decision with its concrete evidence shape."""

        self._events.emit(
            event,
            state=_key(state),
            left_location=_key(left.id),
            left_object=_key(left.object_id),
            left_offset=[left.offset_lower, left.offset_upper],
            right_location=_key(right.id),
            right_object=_key(right.object_id),
            right_offset=[right.offset_lower, right.offset_upper],
            alias=result.kind.value,
            evidence=list(result.evidence),
            completeness=result.assessment.status.value,
            precision=result.assessment.precision.value,
        )

    def havoc(
        self,
        state: MemoryVersionId,
        regions: Sequence[str],
        reason: str,
        origin: str,
        guard: SymbolicExprId | None = None,
    ) -> MemoryVersionId:
        """Create an explicit unknown external effect over named regions."""

        self.validate_current()
        self.calls["havoc"] += 1
        result = self.engine.havoc(
            state,
            regions,
            reason,
            origin,
            guard,
        )
        self._events.emit(
            "memory.havoc.completed",
            parent_state=_key(state),
            state=_key(result),
            regions=list(regions),
            reason=reason,
            origin=origin,
            guard=_key(guard),
        )
        return result

    def definitions(self, read: ReadMemory) -> DefinitionResult:
        """Resolve reaching memory definitions for a versioned read."""

        self.validate_current()
        self.calls["resolve_definition"] += 1
        result = self.engine.resolve_definition(read, self.budget)
        self._events.emit(
            "memory.definitions.completed",
            state=_key(read.state),
            location=_key(read.location),
            result=_key(read.result),
            definitions=[_key(item) for item in result.definitions],
            definition_count=len(result.definitions),
            completeness=result.assessment.status.value,
            precision=result.assessment.precision.value,
            origin=read.origin,
        )
        return result

    def read_definition(
        self,
        result: SymbolicExprId,
        guard: SymbolicExprId | None,
        origin: str,
    ) -> DefinitionResult:
        """Resolve definitions for an existing SSE memory-read leaf."""

        node = self.engine.dag.nodes[result]
        if node.op != SymbolicOp.MEMORY_READ:
            raise ValueError("Definition query needs a versioned read leaf")
        return self.definitions(
            ReadMemory(node.state, node.location, result, guard, origin)
        )

    def candidates(
        self,
        reference: SymbolicExprId,
        limit: int = 64,
    ) -> tuple[tuple[int | bool, ...], bool, tuple[object, ...]]:
        """Enumerate bounded concrete candidates from a resolved SSE DAG.

        Returns:
            Sorted concrete values, an unknown-remainder flag and assessments
            collected by the definition resolver.
        """

        self.validate_current()
        root, resolver = self.engine.resolve(reference, self.budget)
        dag = self.engine.dag
        done: dict[SymbolicExprId, tuple[set[int | bool], bool]] = {}
        stack = [(root, False)]
        while stack:
            current, ready = stack.pop()
            if current in done:
                continue
            node = dag.nodes[current]
            if not ready and node.operands:
                stack.append((current, True))
                stack.extend(
                    (operand, False)
                    for operand in node.operands
                    if operand not in done
                )
                continue
            value = dag.constant_value(current)
            if value is not None:
                values, top = {value}, False
            elif node.op == SymbolicOp.IF:
                left = done[node.operands[1]]
                right = done[node.operands[2]]
                values = left[0] | right[0]
                top = left[1] or right[1]
            elif node.operands:
                values = set()
                top = any(done[operand][1] for operand in node.operands)
                amount = 1
                for operand in node.operands:
                    amount *= len(done[operand][0])
                if amount > limit:
                    raise BudgetExceeded("alias_candidates", limit, amount)
                combinations = product(
                    *(done[operand][0] for operand in node.operands)
                )
                for args in combinations:
                    item = dag._calculate(node, args)
                    if item is not None:
                        if node.type.kind != TypeKind.BOOL:
                            item %= 1 << node.type.bits
                        values.add(item)
            else:
                values, top = set(), True
            if len(values) > limit:
                raise BudgetExceeded("alias_candidates", limit, len(values))
            done[current] = values, top
        values, unknown_remainder = done[root]
        assessments = tuple(resolver.assessments)
        result = tuple(sorted(values)), unknown_remainder, assessments
        self._events.emit(
            "sse.candidates.completed",
            expression=_key(reference),
            resolved_expression=_key(root),
            candidates=list(result[0]),
            candidate_count=len(result[0]),
            unknown_remainder=unknown_remainder,
            assessments=len(assessments),
            limit=limit,
        )
        return result

    def metrics(self) -> dict[str, object]:
        """Return engine, port, cache and sampled-event counters."""

        result = {
            **self.engine.metrics(),
            "memory_port_calls": dict(self.calls),
            "diagnostic_event_counts": self._events.counts(),
        }
        if self._alias_cache_enabled:
            result.update(
                alias_cache_hits=self._alias_hits,
                alias_cache_misses=self._alias_misses,
                alias_cache_entries=len(self._alias_cache),
            )
        return result
