"""P2 session ownership, graph revisions, cache invalidation, and visible budgets.

Single-owner sessions are not a concurrent mutation API. Heap/MemoryVersion,
expression arenas and worklists belong to later phases and are not simulated.
"""
from dataclasses import dataclass
from types import MappingProxyType
from uuid import uuid4

from .identity import (FunctionId, ContextId, MemoryKind, integer, text, typed)
from .program import Completeness, Program, MemoryObject


class BudgetExceeded(RuntimeError):
    pass


@dataclass(frozen=True)
class BudgetLimits:
    max_graph_nodes: int = 100000
    max_graph_edges: int = 1000000
    max_context_depth: int = 64
    max_contexts: int = 10000
    max_objects: int = 100000
    max_cache_entries: int = 10000
    max_summary_entries: int = 10000

    def __post_init__(self):
        for name, value in vars(self).items():
            integer(value, name, 1)


@dataclass(frozen=True)
class Diagnostic:
    code: str
    message: str
    status: Completeness = Completeness.INCOMPLETE


@dataclass(frozen=True)
class RevisionStamp:
    session_id: str
    state_revision: int


@dataclass(frozen=True)
class CacheEntry:
    stamp: RevisionStamp
    value: object


def portable_value(value):
    """P2 cached payloads contain scalar metadata/IDs, never native ASTs."""
    stack = [value]
    visited = 0
    while stack:
        node = stack.pop()
        visited += 1
        if visited > 10000:
            raise ValueError('Cache payload exceeds the metadata node budget')
        if type(node) is tuple:
            stack.extend(node)
        elif node is not None and type(node) not in (str, int, bool):
            raise TypeError('Cache payload must be immutable scalar/tuple metadata')


class AnalysisSession:
    def __init__(self, program, budgets=None):
        # Local import prevents the core/graph package export cycle.
        from emtaint.graph import ControlFlowGraph, CallGraph, CallEdge, TargetKind
        typed(program, Program, 'session program')
        self._program = program
        self._budgets = budgets if budgets is not None else BudgetLimits()
        typed(self._budgets, BudgetLimits, 'session budgets')
        self._session_id = uuid4().hex
        self._revision = 0
        self._diagnostics = []
        self._limit('graph nodes', sum(len(f.blocks) for f in program.functions) + len(program.functions),
                    self.budgets.max_graph_nodes)
        self._limit('graph edges', len(program.callsites), self.budgets.max_graph_edges)
        self._cfgs = {f.id: ControlFlowGraph(f.id, frozenset(b.id for b in f.blocks), entry=f.entry)
                      for f in program.functions}
        self._cg = CallGraph(frozenset(f.id for f in program.functions), frozenset(
            CallEdge(s.id, None, TargetKind.UNKNOWN, 'Call targets not imported') for s in program.callsites))
        self._check_graph_budget(self._cfgs, self._cg)
        self._cfg_versions = {f: 0 for f in self._cfgs}
        self._cg_version = 0
        self._cache = {}
        self._summaries = {}
        self._contexts = {ContextId()}
        self._objects = {}

    @property
    def program(self):
        return self._program

    @property
    def budgets(self):
        return self._budgets

    @property
    def stamp(self):
        return RevisionStamp(self._session_id, self._revision)

    @property
    def cfgs(self):
        return MappingProxyType(self._cfgs)

    def cfg(self, function):
        return self._cfgs[function]

    def cfg_version(self, function):
        return self._cfg_versions[function]

    @property
    def cg(self):
        return self._cg

    @property
    def cg_version(self):
        return self._cg_version

    @property
    def objects(self):
        return MappingProxyType(self._objects)

    @property
    def contexts(self):
        return frozenset(self._contexts)

    @property
    def diagnostics(self):
        return tuple(self._diagnostics)

    @property
    def status(self):
        statuses = [self.program.status, self.cg.status]
        statuses.extend(g.status for g in self._cfgs.values())
        statuses.extend(d.status for d in self._diagnostics)
        if Completeness.INCOMPLETE in statuses:
            return Completeness.INCOMPLETE
        return Completeness.UNKNOWN if Completeness.UNKNOWN in statuses else Completeness.COMPLETE

    def _limit(self, name, count, maximum):
        if count > maximum:
            message = name + ' budget exceeded: ' + str(count) + ' > ' + str(maximum)
            self._diagnostics.append(Diagnostic('BUDGET_EXCEEDED', message))
            raise BudgetExceeded(message)

    def _check_graph_budget(self, cfgs, cg):
        self._limit('graph nodes', sum(len(g.nodes) for g in cfgs.values()) + len(cg.nodes), self.budgets.max_graph_nodes)
        self._limit('graph edges', sum(len(g.edges) for g in cfgs.values()) + len(cg.edges), self.budgets.max_graph_edges)

    def _invalidate(self):
        self._revision += 1
        self._cache.clear()
        self._summaries.clear()

    def invalidate_semantics(self, function, reason):
        """Invalidate scoped handles after a body/summary semantic change.

        The CFG/CG topology versions do not change merely because a recipe
        changes. The global state revision still rejects stale memory handles.
        """
        self.program.function(function)
        text(reason, 'semantic invalidation reason')
        self._invalidate()

    def replace_cfg(self, cfg):
        from emtaint.graph import ControlFlowGraph
        typed(cfg, ControlFlowGraph, 'CFG')
        if cfg.function not in self._cfgs:
            raise ValueError('CFG function is outside this program')
        function = self.program.function(cfg.function)
        if cfg.nodes != frozenset(b.id for b in function.blocks) or cfg.entry != function.entry:
            raise ValueError('CFG must retain the function block set and declared entry')
        if cfg == self._cfgs[cfg.function]:
            return
        candidate = dict(self._cfgs)
        candidate[cfg.function] = cfg
        self._check_graph_budget(candidate, self.cg)
        self._cfgs[cfg.function] = cfg
        self._cfg_versions[cfg.function] += 1
        self._invalidate()

    def replace_cg(self, cg):
        """Replace the call graph after validating its completeness."""

        from emtaint.graph import CallGraph

        # Validate the input type before comparing graph state.
        typed(cg, CallGraph, 'call graph')

        # Ensure every declared function is retained.
        expected_nodes = frozenset(
            function.id for function in self.program.functions
        )
        if cg.nodes != expected_nodes:
            raise ValueError('CG must retain every declared function')

        # Ensure every declared callsite has an explicit graph edge.
        expected_callsites = frozenset(
            callsite.id for callsite in self.program.callsites
        )
        actual_callsites = frozenset(
            edge.site for edge in cg.edges
        )
        if actual_callsites != expected_callsites:
            raise ValueError(
                'Each declared callsite needs a target or explicit unknown edge'
            )

        # Avoid unnecessary updates when the graph is unchanged.
        if cg == self.cg:
            return

        # Validate resource constraints before committing the update.
        self._check_graph_budget(self._cfgs, cg)

        # Commit the new graph and invalidate dependent analyses.
        self._cg = cg
        self._cg_version += 1
        self._invalidate()

    def _validate_context(self, context):
        typed(context, ContextId, 'analysis context')
        self._limit('context depth', len(context.call_string), self.budgets.max_context_depth)
        for site in context.call_string:
            try:
                self.program.callsite(site)
            except KeyError as error:
                raise ValueError('Context contains an undeclared callsite') from error

    def register_context(self, context):
        self._validate_context(context)
        self._limit('contexts', len(self._contexts) + int(context not in self._contexts), self.budgets.max_contexts)
        self._contexts.add(context)

    def register_object(self, obj):
        typed(obj, MemoryObject, 'memory descriptor')
        identity = obj.id
        if identity.binary != self.program.binary:
            raise ValueError('Memory object belongs to another image')
        if identity.function is not None:
            try:
                self.program.function(identity.function)
            except KeyError as error:
                raise ValueError('Memory object function is undeclared') from error
        if identity.site is not None:
            self.program.validate_point(identity.site)
        if identity.kind == MemoryKind.GLOBAL:
            self.program.absolute_address(identity.coordinates[1])
        if identity.context is not None:
            self._validate_context(identity.context)
            self._limit('contexts', len(self._contexts) + int(identity.context not in self._contexts), self.budgets.max_contexts)
        if identity in self._objects:
            if self._objects[identity] != obj:
                raise ValueError('Conflicting descriptor for the same object identity')
            return
        self._limit('memory object identities', len(self._objects) + 1, self.budgets.max_objects)
        self._objects[identity] = obj
        if identity.context is not None:
            self._contexts.add(identity.context)
        # Object-set changes can affect future alias queries: invalidate metadata
        # caches now; this is not a MemoryVersion or a memory write.
        self._invalidate()

    def cache_put(self, namespace, key, value):
        text(namespace, 'cache namespace')
        text(key, 'cache key')
        self._check_payload(value)
        identity = (namespace, key)
        self._limit('cache entries', len(self._cache) + int(identity not in self._cache), self.budgets.max_cache_entries)
        self._cache[identity] = CacheEntry(self.stamp, value)

    def _check_payload(self, value):
        try:
            portable_value(value)
        except ValueError as error:
            self._diagnostics.append(Diagnostic('BUDGET_EXCEEDED', str(error)))
            raise BudgetExceeded(str(error)) from error

    def cache_get(self, namespace, key):
        entry = self._cache.get((namespace, key))
        return entry if entry is not None and entry.stamp == self.stamp else None

    def summary_put(self, function, context, value):
        typed(function, FunctionId, 'summary function')
        self.program.function(function)
        self._validate_context(context)
        self._check_payload(value)
        key = (function, context)
        self._limit('summary entries', len(self._summaries) + int(key not in self._summaries), self.budgets.max_summary_entries)
        self.register_context(context)
        self._summaries[key] = CacheEntry(self.stamp, value)

    def summary_get(self, function, context):
        entry = self._summaries.get((function, context))
        return entry if entry is not None and entry.stamp == self.stamp else None
