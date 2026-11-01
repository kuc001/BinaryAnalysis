"""Memory-Semantics-v1 path/APG descriptors. No alias or widening algorithm."""
from dataclasses import dataclass

from emtaint.core import Endian, MemoryObjectId, ProgramPoint, Completeness
from emtaint.core.contracts import (Record, Assessment, Precision, SymbolicExprId,
    AccessPathId, AccessGraphId, bits, key, same_scope)
from emtaint.core.identity import integer, text


@dataclass(frozen=True)
class AccessRoot(Record):
    object_id: MemoryObjectId
    region: str
    address_space: str
    origin: str

    def __post_init__(self):
        super().__post_init__()
        for value in (self.region, self.address_space, self.origin):
            text(value, 'root metadata')


@dataclass(frozen=True)
class Offset(Record):
    delta_bytes: int


@dataclass(frozen=True)
class Deref(Record):
    pointer_bits: int
    value_bits: int
    endian: Endian
    address_space: str = 'default'

    def __post_init__(self):
        super().__post_init__()
        bits(self.pointer_bits)
        bits(self.value_bits, byte_access=True)
        text(self.address_space, 'deref address space')


def interval(lower, upper):
    if (lower is None) != (upper is None) or (lower is not None and lower > upper):
        raise ValueError('Interval needs ordered endpoints or an explicit unbounded pair')


@dataclass(frozen=True)
class Index(Record):
    expression: SymbolicExprId
    stride_bytes: int
    lower: int | None = None
    upper: int | None = None

    def __post_init__(self):
        super().__post_init__()
        integer(self.stride_bytes, 'index stride', 1)
        interval(self.lower, self.upper)


@dataclass(frozen=True)
class UnknownOffset(Record):
    lower: int | None
    upper: int | None
    reason: str

    def __post_init__(self):
        super().__post_init__()
        interval(self.lower, self.upper)
        text(self.reason, 'unknown offset reason')


AccessSegment = Offset | Deref | Index | UnknownOffset


def validate_segments(scope, segments):
    for segment in segments:
        if isinstance(segment, Index):
            same_scope(scope, segment.expression)


@dataclass(frozen=True)
class AccessPath(Record):
    id: AccessPathId
    root: AccessRoot
    segments: tuple[AccessSegment, ...]
    width_bits: int
    endian: Endian
    origin: str
    assessment: Assessment = Assessment()

    def __post_init__(self):
        super().__post_init__()
        bits(self.width_bits)
        key(self.origin)
        if self.root.object_id.binary != self.id.scope.function.binary:
            raise ValueError('Root belongs to another binary')
        validate_segments(self.id.scope, self.segments)
        if self.segments and isinstance(self.segments[-1], Deref) and self.segments[-1].value_bits != self.width_bits:
            raise ValueError('Final dereference width differs from the path value width')

    @property
    def deref_count(self):
        return sum(isinstance(segment, Deref) for segment in self.segments)


@dataclass(frozen=True)
class APGNode(Record):
    id: str
    root: AccessRoot | None = None

    def __post_init__(self):
        super().__post_init__()
        key(self.id)


@dataclass(frozen=True)
class APGEdge(Record):
    source: str
    target: str
    label: AccessSegment

    def __post_init__(self):
        super().__post_init__()
        key(self.source)
        key(self.target)


@dataclass(frozen=True)
class APGSummary(Record):
    source: str
    target: str
    pattern: tuple[AccessSegment, ...]
    minimum_repetitions: int
    maximum_repetitions: int | None
    trigger: ProgramPoint
    reason: str
    coverage_argument: str
    precision_loss: str
    soundness: Completeness = Completeness.UNKNOWN

    def __post_init__(self):
        super().__post_init__()
        key(self.source)
        key(self.target)
        if not self.pattern:
            raise ValueError('Summary requires a nonempty field pattern')
        integer(self.minimum_repetitions, 'minimum repetitions')
        if self.maximum_repetitions is not None and self.maximum_repetitions < self.minimum_repetitions:
            raise ValueError('Invalid summary repetition bounds')
        for value in (self.reason, self.coverage_argument, self.precision_loss):
            text(value, 'summary provenance/coverage claim')


@dataclass(frozen=True)
class AccessGraph(Record):
    id: AccessGraphId
    nodes: tuple[APGNode, ...]
    edges: tuple[APGEdge, ...]
    summaries: tuple[APGSummary, ...]
    entries: tuple[str, ...]
    accepting: tuple[str, ...]
    assessment: Assessment = Assessment()

    def __post_init__(self):
        super().__post_init__()
        nodes = {node.id for node in self.nodes}
        if len(nodes) != len(self.nodes) or not set(self.entries + self.accepting) <= nodes:
            raise ValueError('Duplicate APG node or dangling entry/accepting node')
        for edge in self.edges + self.summaries:
            if edge.source not in nodes or edge.target not in nodes:
                raise ValueError('Dangling APG edge')
            validate_segments(self.id.scope, (edge.label,) if isinstance(edge, APGEdge) else edge.pattern)
        if self.summaries:
            if self.assessment.precision == Precision.EXACT:
                raise ValueError('Path summary must declare abstraction/precision loss')
            if not self.assessment.precision_loss:
                raise ValueError('Path summary needs explicit precision-loss diagnostics')
            if self.assessment.status == Completeness.COMPLETE and any(s.soundness != Completeness.COMPLETE for s in self.summaries):
                raise ValueError('Unverified summary cannot declare a complete graph')


def modular_offset(delta, pointer_bits):
    """Representation helper only; no dereference or memory read is performed."""
    integer(delta, 'pointer offset', minimum=None)
    bits(pointer_bits)
    return delta % (1 << pointer_bits)
