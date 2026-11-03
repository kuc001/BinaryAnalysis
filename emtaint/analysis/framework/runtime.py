"""Session-owned dependency caches, graph updates and stale-reference checks.

P2's global graph stamp invalidates raw P3 scoped handles. Unaffected scalar
metadata caches survive by a per-function epoch. Rich scoped values must be
rebuilt or rebased explicitly; they are never silently reused as current heap
states.
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass, fields, is_dataclass
from enum import Enum
import logging

from emtaint.core import (
    AnalysisSession,
    ContextId,
    FunctionId,
    Program,
)
from emtaint.debugging import EventSampler, function_address_fields, log_event
from emtaint.graph import CallEdge, CallGraph, ControlFlowGraph


LOGGER = logging.getLogger(__name__)


class StaleAnalysis(ValueError):
    """Raised when a scoped handle predates a CFG or call-graph revision."""


@dataclass(frozen=True)
class AnalysisHandle:
    """Identity of one function/context view at a graph revision."""

    session: str
    revision: int
    function: FunctionId
    context: ContextId


class AnalysisRuntime:
    """Own versioned analysis caches, ports, summaries and dependency updates.

    Args:
        program: Immutable program model used to create the analysis session.
    """

    NAMESPACES = frozenset(
        ("heap", "alias", "sse", "apg", "summary", "facts", "result")
    )
    INFERRED_PREFIX = "P6 derived CIR target: "

    def __init__(self, program: Program) -> None:
        self.session = AnalysisSession(program)
        self._cache: dict[tuple[object, ...], tuple[int, object]] = {}
        self.epochs = {function.id: 0 for function in program.functions}
        self.pending: set[FunctionId] = set()
        self.events: list[tuple[str, tuple[int, ...], int]] = []
        self.ports: dict[tuple[FunctionId, ContextId], object] = {}
        self.active: set[FunctionId] = set()
        self.metadata_invalidated: set[FunctionId] = set()
        self._recipes: dict[tuple[FunctionId, ContextId], tuple[int, object]] = {}
        self._diagnostics = EventSampler(LOGGER)
        log_event(
            LOGGER,
            "analysis.runtime.initialized",
            functions=len(program.functions),
            cfgs=len(self.session.cfgs),
            cg_edges=len(self.session.cg.edges),
            revision=self.session.stamp.state_revision,
        )

    def handle(
        self,
        function: FunctionId,
        context: ContextId,
    ) -> AnalysisHandle:
        """Create a current scoped handle and mark the function active."""

        self.session.program.function(function)
        self.session.register_context(context)
        self.active.add(function)
        handle = AnalysisHandle(
            self.session.stamp.session_id,
            self.session.stamp.state_revision,
            function,
            context,
        )
        self._diagnostics.emit(
            "analysis.handle.created",
            **function_address_fields(
                function.rva,
                self.session.program.image_base,
            ),
            context=context.token,
            revision=handle.revision,
        )
        return handle

    def validate(self, handle: AnalysisHandle) -> None:
        """Reject a handle whose session or graph revision is stale."""

        current = (
            self.session.stamp.session_id,
            self.session.stamp.state_revision,
        )
        if (handle.session, handle.revision) != current:
            log_event(
                LOGGER,
                "analysis.handle.stale",
                level=logging.WARNING,
                **function_address_fields(
                    handle.function.rva,
                    self.session.program.image_base,
                ),
                handle_revision=handle.revision,
                current_revision=current[1],
            )
            raise StaleAnalysis("Graph/object revision changed; scoped state is stale")

    def put(
        self,
        namespace: str,
        function: FunctionId,
        context: ContextId,
        key: object,
        payload: object,
    ) -> None:
        """Store portable scalar metadata under the function's current epoch."""

        if namespace not in self.NAMESPACES:
            raise ValueError("Unknown cache family")
        from emtaint.core.session import portable_value

        portable_value(payload)
        self.session.program.function(function)
        self.session.register_context(context)
        self.active.add(function)
        cache_key = (namespace, function, context, key)
        if (
            len(self._cache) >= self.session.budgets.max_cache_entries
            and cache_key not in self._cache
        ):
            raise ValueError("P6 cache budget exhausted; incomplete")
        self._cache[cache_key] = (self.epochs[function], payload)
        self._diagnostics.emit(
            "analysis.cache.stored",
            namespace=namespace,
            **function_address_fields(
                function.rva,
                self.session.program.image_base,
            ),
            context=context.token,
            epoch=self.epochs[function],
            cache_entries=len(self._cache),
        )

    def get(
        self,
        namespace: str,
        function: FunctionId,
        context: ContextId,
        key: object,
    ) -> object | None:
        """Return a cache value only when its function epoch is current."""

        entry = self._cache.get((namespace, function, context, key))
        hit = entry is not None and entry[0] == self.epochs[function]
        self._diagnostics.emit(
            "analysis.cache.lookup",
            namespace=namespace,
            **function_address_fields(
                function.rva,
                self.session.program.image_base,
            ),
            context=context.token,
            epoch=self.epochs[function],
            hit=hit,
        )
        return entry[1] if hit else None

    def _affected(
        self,
        seeds: Iterable[FunctionId],
        graphs: Sequence[CallGraph],
    ) -> frozenset[FunctionId]:
        """Compute the reverse-call closure invalidated by changed callees."""

        affected = set(seeds)
        while True:
            updated = affected | {
                edge.site.function
                for graph in graphs
                for edge in graph.edges
                if edge.target in affected
            }
            if updated == affected:
                return frozenset(affected)
            affected = updated

    def _invalidate(
        self,
        affected: Iterable[FunctionId],
        reason: str,
    ) -> None:
        """Advance epochs and evict scoped state for an affected closure."""

        affected = frozenset(affected)
        cache_before = len(self._cache)
        ports_before = len(self.ports)
        recipes_before = len(self._recipes)
        for function in affected:
            self.epochs[function] += 1
        self._cache = {
            key: value
            for key, value in self._cache.items()
            if key[1] not in affected
        }
        self.ports = {
            key: value
            for key, value in self.ports.items()
            if key[0] not in affected
        }
        self._recipes = {
            key: value
            for key, value in self._recipes.items()
            if key[0] not in affected
        }
        self.pending.update(set(affected) & self.active)
        self.metadata_invalidated.update(set(affected) - self.active)
        addresses = tuple(sorted(function.rva for function in affected))
        revision = self.session.stamp.state_revision
        self.events.append((reason, addresses, revision))
        log_event(
            LOGGER,
            "analysis.dependencies.invalidated",
            level=logging.INFO,
            reason=reason,
            affected=[hex(address) for address in addresses],
            affected_count=len(affected),
            active_pending=len(set(affected) & self.active),
            metadata_invalidated=len(set(affected) - self.active),
            cache_evicted=cache_before - len(self._cache),
            ports_evicted=ports_before - len(self.ports),
            recipes_evicted=recipes_before - len(self._recipes),
            revision=revision,
        )

    def replace_cfg(
        self,
        cfg: ControlFlowGraph,
    ) -> frozenset[FunctionId]:
        """Replace a changed CFG and invalidate its reverse-call closure."""

        old = self.session.cfg(cfg.function)
        if cfg == old:
            return frozenset()
        self.session.replace_cfg(cfg)
        affected = self._affected((cfg.function,), (self.session.cg,))
        log_event(
            LOGGER,
            "cfg.replaced",
            level=logging.INFO,
            **function_address_fields(
                cfg.function.rva,
                self.session.program.image_base,
            ),
            nodes_before=len(old.nodes),
            nodes_after=len(cfg.nodes),
            edges_before=len(old.edges),
            edges_after=len(cfg.edges),
            revision=self.session.stamp.state_revision,
        )
        self._invalidate(affected, "CFG changed")
        return affected

    def add_call_edge(self, edge: CallEdge) -> frozenset[FunctionId]:
        """Add one call edge using the same revision path as a batch."""

        return self.add_call_edges((edge,))

    def invalidate_dependencies(
        self,
        functions: Iterable[FunctionId],
        reason: str,
    ) -> frozenset[FunctionId]:
        """Invalidate semantic summaries and their real reverse-CG callers."""

        functions = frozenset(functions)
        if not functions:
            return frozenset()
        for function in functions:
            self.session.invalidate_semantics(function, reason)
        affected = self._affected(functions, (self.session.cg,))
        self._invalidate(affected, reason)
        return affected

    def add_call_edges(
        self,
        edges: Iterable[CallEdge],
    ) -> frozenset[FunctionId]:
        """Add new may/confirmed call edges and invalidate dependent callers."""

        old = self.session.cg
        additions = frozenset(edges) - old.edges
        if not additions:
            return frozenset()
        # Retain unresolved edges until exhaustive, independently justified
        # resolution; a may-candidate cannot erase the unknown remainder.
        graph = CallGraph(
            old.nodes,
            old.edges | additions,
            old.status,
            old.reason,
        )
        self.session.replace_cg(graph)
        affected = self._affected(
            tuple(edge.site.function for edge in additions),
            (old, graph),
        )
        log_event(
            LOGGER,
            "cg.edges.added",
            level=logging.INFO,
            additions=len(additions),
            edges_before=len(old.edges),
            edges_after=len(graph.edges),
            callsites=len({edge.site for edge in additions}),
            revision=self.session.stamp.state_revision,
        )
        self._invalidate(affected, "CG target added")
        return affected

    def replace_inferred_call_edges(
        self,
        sites: Iterable[object],
        edges: Iterable[CallEdge],
    ) -> frozenset[FunctionId]:
        """Replace stale derived facts while preserving static/imported proof."""

        old = self.session.cg
        sites = frozenset(sites)
        retained = frozenset(
            edge
            for edge in old.edges
            if not (
                edge.site in sites
                and edge.reason.startswith(self.INFERRED_PREFIX)
            )
        )
        graph = CallGraph(
            old.nodes,
            retained | frozenset(edges),
            old.status,
            old.reason,
        )
        if graph == old:
            return frozenset()
        self.session.replace_cg(graph)
        changed = old.edges ^ graph.edges
        affected = self._affected(
            tuple(edge.site.function for edge in changed),
            (old, graph),
        )
        log_event(
            LOGGER,
            "cg.inferred_edges.replaced",
            level=logging.INFO,
            sites=len(sites),
            changed_edges=len(changed),
            edges_before=len(old.edges),
            edges_after=len(graph.edges),
            revision=self.session.stamp.state_revision,
        )
        self._invalidate(affected, "CG derived facts replaced")
        return affected

    def recipe_get(
        self,
        function: FunctionId,
        context: ContextId,
    ) -> object | None:
        """Return a detached procedure recipe at the current function epoch."""

        entry = self._recipes.get((function, context))
        return (
            entry[1]
            if entry is not None and entry[0] == self.epochs[function]
            else None
        )

    def recipe_put(
        self,
        function: FunctionId,
        context: ContextId,
        recipe: object,
    ) -> frozenset[FunctionId]:
        """Store one detached immutable recipe and invalidate changed users."""

        from emtaint.core.contracts import ScopedId

        if recipe.function != function:
            raise ValueError("Recipe belongs to a different function")
        pending = [recipe]
        seen = set()
        while pending:
            value = pending.pop()
            if isinstance(value, ScopedId):
                raise ValueError("Recipe cannot retain scoped memory/SSE/APG IDs")
            if value is None or type(value) in (int, str, bool) or isinstance(value, Enum):
                continue
            if id(value) in seen:
                continue
            seen.add(id(value))
            if type(value) is tuple:
                pending.extend(value)
            elif (
                is_dataclass(value)
                and value.__dataclass_params__.frozen
                and type(value).__module__.startswith("emtaint.")
            ):
                pending.extend(getattr(value, field.name) for field in fields(value))
            else:
                raise TypeError("Recipe must be detached immutable analysis metadata")
        self.session.program.function(function)
        self.session.register_context(context)
        self.active.add(function)
        old = self.recipe_get(function, context)
        if old == recipe:
            return frozenset()
        affected = frozenset()
        if old is not None:
            self.session.invalidate_semantics(function, "Procedure recipe changed")
            affected = self._affected((function,), (self.session.cg,))
            self._invalidate(affected, "Procedure recipe changed")
        self._recipes[(function, context)] = (self.epochs[function], recipe)
        self.session.summary_put(
            function,
            context,
            (
                "detached-procedure-recipe",
                len(recipe.nodes),
                len(recipe.returns),
            ),
        )
        log_event(
            LOGGER,
            "summary.recipe.stored",
            **function_address_fields(
                function.rva,
                self.session.program.image_base,
            ),
            context=context.token,
            nodes=len(recipe.nodes),
            returns=len(recipe.returns),
            changed=old is not None,
            affected=len(affected),
        )
        return affected

    def bind_port(
        self,
        port: object,
        function: FunctionId,
        context: ContextId,
    ) -> None:
        """Bind a current scoped MemoryQueryPort to a function/context pair."""

        port.scope.assert_current(self.session)
        if port.scope.function != function or port.scope.context != context:
            raise ValueError("Port function/context mismatch")
        handle = self.handle(function, context)
        port.validate_current = lambda: self.validate(handle)
        self.ports[(function, context)] = port
        log_event(
            LOGGER,
            "memory.port.bound",
            **function_address_fields(
                function.rva,
                self.session.program.image_base,
            ),
            context=context.token,
            revision=handle.revision,
            active_ports=len(self.ports),
        )

    def memory_put(
        self,
        namespace: str,
        handle: AnalysisHandle,
        memory: object,
        key: object,
        payload: object,
    ) -> None:
        """Store metadata keyed by a validated scoped memory version."""

        self.validate(handle)
        memory.scope.assert_current(self.session)
        if (
            memory.scope.function != handle.function
            or memory.scope.context != handle.context
        ):
            raise ValueError("Cache memory/context mismatch")
        self.put(
            namespace,
            handle.function,
            handle.context,
            (memory, key),
            payload,
        )

    def memory_get(
        self,
        namespace: str,
        handle: AnalysisHandle,
        memory: object,
        key: object,
    ) -> object | None:
        """Read metadata keyed by a validated scoped memory version."""

        self.validate(handle)
        memory.scope.assert_current(self.session)
        return self.get(
            namespace,
            handle.function,
            handle.context,
            (memory, key),
        )
