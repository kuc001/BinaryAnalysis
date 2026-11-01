"""Immutable CFG/CG snapshots. No native node objects and no solver semantics."""
from dataclasses import dataclass, replace
from enum import Enum

from emtaint.core.identity import FunctionId, BlockId, CallSiteId, text, typed
from emtaint.core.program import Completeness


def frozen_of(values, kind, name):
    if type(values) is not frozenset:
        raise TypeError(name + ' must be a frozenset')
    for value in values:
        typed(value, kind, name + ' item')


class FlowKind(str, Enum):
    FALL_THROUGH = 'fall_through'
    TRUE = 'true'
    FALSE = 'false'
    SWITCH = 'switch'
    JUMP = 'jump'
    EXCEPTION = 'exception'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class FlowEdge:
    source: BlockId
    target: BlockId
    kind: FlowKind = FlowKind.FALL_THROUGH
    label: str = ''

    def __post_init__(self):
        typed(self.source, BlockId, 'flow source')
        typed(self.target, BlockId, 'flow target')
        typed(self.kind, FlowKind, 'flow kind')
        text(self.label, 'edge label', allow_empty=True)
        if self.source.function != self.target.function:
            raise ValueError('Intraprocedural CFG cannot contain a cross-function edge')


@dataclass(frozen=True)
class ControlFlowGraph:
    function: FunctionId
    nodes: frozenset[BlockId]
    edges: frozenset[FlowEdge] = frozenset()
    entry: BlockId | None = None
    exits: frozenset[BlockId] = frozenset()
    status: Completeness = Completeness.UNKNOWN
    reason: str = 'Control-flow edges not imported'

    def __post_init__(self):
        typed(self.function, FunctionId, 'CFG function')
        frozen_of(self.nodes, BlockId, 'CFG nodes')
        frozen_of(self.edges, FlowEdge, 'CFG edges')
        frozen_of(self.exits, BlockId, 'CFG exits')
        typed(self.status, Completeness, 'CFG completeness')
        text(self.reason, 'CFG reason', allow_empty=self.status == Completeness.COMPLETE)
        if any(node.function != self.function for node in self.nodes):
            raise ValueError('CFG contains a foreign block')
        if self.entry is not None and self.entry not in self.nodes:
            raise ValueError('CFG entry is not registered')
        if not self.exits <= self.nodes:
            raise ValueError('CFG exits are not registered')
        if any(e.source not in self.nodes or e.target not in self.nodes for e in self.edges):
            raise ValueError('Dangling CFG edge')
        if self.status == Completeness.COMPLETE and any(e.kind == FlowKind.UNKNOWN for e in self.edges):
            raise ValueError('Unknown flow cannot be declared complete')
        if self.status == Completeness.COMPLETE and self.nodes and self.entry is None:
            raise ValueError('Complete non-empty CFG requires a declared entry')

    def with_edge(self, edge):
        return replace(self, edges=self.edges | frozenset((edge,)))

    def without_edge(self, edge):
        return replace(self, edges=self.edges - frozenset((edge,)))

    def successors(self, node):
        return frozenset(e.target for e in self.edges if e.source == node)

    def predecessors(self, node):
        return frozenset(e.source for e in self.edges if e.target == node)


class TargetKind(str, Enum):
    CONFIRMED = 'confirmed'
    MAY = 'may'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class CallEdge:
    site: CallSiteId
    target: FunctionId | None
    certainty: TargetKind = TargetKind.UNKNOWN
    reason: str = ''

    def __post_init__(self):
        typed(self.site, CallSiteId, 'callsite')
        typed(self.certainty, TargetKind, 'target certainty')
        text(self.reason, 'target reason', allow_empty=self.certainty == TargetKind.CONFIRMED)
        if self.target is not None:
            typed(self.target, FunctionId, 'call target')
        if (self.target is None) != (self.certainty == TargetKind.UNKNOWN):
            raise ValueError('Only an unknown call edge has no concrete target ID')


@dataclass(frozen=True)
class CallGraph:
    nodes: frozenset[FunctionId]
    edges: frozenset[CallEdge] = frozenset()
    status: Completeness = Completeness.UNKNOWN
    reason: str = 'Call targets not established'

    def __post_init__(self):
        frozen_of(self.nodes, FunctionId, 'CG nodes')
        frozen_of(self.edges, CallEdge, 'CG edges')
        typed(self.status, Completeness, 'CG completeness')
        text(self.reason, 'CG reason', allow_empty=self.status == Completeness.COMPLETE)
        if any(e.site.function not in self.nodes or (e.target is not None and e.target not in self.nodes) for e in self.edges):
            raise ValueError('Dangling CG edge')
        if self.status == Completeness.COMPLETE and self.unresolved_sites:
            raise ValueError('Unknown targets cannot be declared complete')

    @property
    def unresolved_sites(self):
        return frozenset(e.site for e in self.edges if e.certainty == TargetKind.UNKNOWN)

    def targets(self, site, confirmed_only=False):
        return frozenset(e.target for e in self.edges if e.site == site and e.target is not None
                         and (not confirmed_only or e.certainty == TargetKind.CONFIRMED))

    def with_edge(self, edge):
        return replace(self, edges=self.edges | frozenset((edge,)))

    def without_edge(self, edge):
        return replace(self, edges=self.edges - frozenset((edge,)))
