"""Memory object/location/version/SSE/taint contract records, not a heap engine."""
from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

from emtaint.core import (Architecture, Completeness, ContextId, Endian, MemoryObject,
                           MemoryObjectId)
from emtaint.core.contracts import (Record, Assessment, Precision, Origin, AnalysisScope,
    SymbolicExprId, MemoryVersionId, AccessPathId, AccessGraphId, MemoryLocationId,
    ValueType, TypeKind, Constant, SemanticBudgets, bits, key, same_scope, validate_value_operation)
from emtaint.core.identity import text
from .access_path import AccessRoot, AccessPath, AccessGraph, Index, Deref, interval
from .abstract_heap import HeapObject, HeapCell, ObjectCardinality


@dataclass(frozen=True)
class MemoryLocation(Record):
    """Width/endian-qualified abstract location with explicit offset precision."""

    id: MemoryLocationId
    object_id: MemoryObjectId | None
    offset_lower: int | None
    offset_upper: int | None
    width_bits: int
    endian: Endian
    address_space: str
    origin: str
    assessment: Assessment = Assessment()

    def __post_init__(self):
        super().__post_init__()
        interval(self.offset_lower, self.offset_upper)
        bits(self.width_bits, byte_access=True)
        key(self.origin)
        text(self.address_space, 'location address space')
        if self.object_id is not None and self.object_id.binary != self.id.scope.function.binary:
            raise ValueError('Location belongs to a foreign image')
        if (self.object_id is None or self.offset_lower is None) and self.assessment.status == Completeness.COMPLETE:
            raise ValueError('Unknown object/offset cannot be a complete exact location')

    @property
    def byte_interval(self) -> tuple[int, int] | None:
        """Return the exact half-open byte range, or ``None`` if imprecise."""

        if self.offset_lower is None or self.offset_lower != self.offset_upper:
            return None
        return (self.offset_lower, self.offset_lower + self.width_bits // 8)


class AliasKind(str, Enum):
    """Four-way alias result; unknown is distinct from proven no-alias."""

    MUST = 'must_alias'
    MAY = 'may_alias'
    NO = 'no_alias'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class AliasResult(Record):
    """Alias classification together with evidence and precision assessment."""

    kind: AliasKind
    evidence: tuple[str, ...]
    assessment: Assessment

    def __post_init__(self):
        super().__post_init__()
        if self.kind in (AliasKind.MUST, AliasKind.NO) and (
                not self.evidence or self.assessment.status != Completeness.COMPLETE
                or self.assessment.precision != Precision.EXACT):
            raise ValueError('Must/NoAlias needs explicit exact, complete evidence')

    def __bool__(self):
        raise TypeError('Inspect AliasKind explicitly; unknown is not NoAlias')


class UpdateKind(str, Enum):
    """Strong replacement or conservative weak memory update."""

    STRONG = 'strong'
    WEAK = 'weak'


def select_update_policy(
    alias: AliasResult, unique_target: bool, exact_coverage: bool
) -> UpdateKind:
    """Allow a strong update only for must-alias, unique, exact coverage."""

    if type(unique_target) is not bool or type(exact_coverage) is not bool or not isinstance(alias, AliasResult):
        raise TypeError('Explicit alias evidence and boolean update preconditions required')
    return (UpdateKind.STRONG if alias.kind == AliasKind.MUST and unique_target and exact_coverage
            else UpdateKind.WEAK)


@dataclass(frozen=True)
class InitialMemory(Record):
    """Root definition for a versioned memory graph."""

    origin: str


@dataclass(frozen=True)
class WriteMemory(Record):
    """Guarded memory definition with explicit alias/update evidence."""

    parent: MemoryVersionId
    location: MemoryLocationId
    value: SymbolicExprId
    guard: SymbolicExprId | None
    update: UpdateKind
    alias: AliasResult
    origin: str
    unique_target: bool = False
    exact_coverage: bool = False

    def __post_init__(self):
        super().__post_init__()
        same_scope(self.parent.scope, self.location, self.value, self.guard)
        key(self.origin)
        if self.update == UpdateKind.STRONG and select_update_policy(self.alias, self.unique_target, self.exact_coverage) != UpdateKind.STRONG:
            raise ValueError('Strong update lacks sufficient preconditions')


@dataclass(frozen=True)
class JoinInput(Record):
    """One predecessor memory version and its optional path guard."""

    version: MemoryVersionId
    guard: SymbolicExprId | None

    def __post_init__(self):
        super().__post_init__()
        same_scope(self.version.scope, self.guard)


@dataclass(frozen=True)
class JoinMemory(Record):
    """Phi-like merge of at least two scoped predecessor memory versions."""

    inputs: tuple[JoinInput, ...]
    origin: str

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        if len(self.inputs) < 2:
            raise ValueError('Memory join needs at least two predecessor records')
        same_scope(self.inputs[0].version.scope, *(item.version for item in self.inputs))


@dataclass(frozen=True)
class HavocMemory(Record):
    """Explicit unknown external effect over declared memory regions."""

    parent: MemoryVersionId
    regions: tuple[str, ...]
    reason: str
    origin: str
    guard: SymbolicExprId | None = None

    def __post_init__(self):
        super().__post_init__()
        if not self.regions or any(not r for r in self.regions):
            raise ValueError('Havoc must declare possibly affected regions (* means all)')
        text(self.reason, 'havoc reason')
        key(self.origin)
        same_scope(self.parent.scope, self.guard)


MemoryDefinition = InitialMemory | WriteMemory | JoinMemory | HavocMemory


@dataclass(frozen=True)
class MemoryVersion(Record):
    """Immutable memory-state identity and the definition that produced it."""

    id: MemoryVersionId
    definition: MemoryDefinition

    def __post_init__(self):
        super().__post_init__()
        same_scope(self.id.scope, *self.parents)
        if self.id in self.parents:
            raise ValueError('Memory version cannot define itself')

    @property
    def parents(self) -> tuple[MemoryVersionId, ...]:
        """Return direct predecessor versions without traversing history."""

        if isinstance(self.definition, InitialMemory):
            return ()
        if isinstance(self.definition, JoinMemory):
            return tuple(item.version for item in self.definition.inputs)
        return (self.definition.parent,)


@dataclass(frozen=True)
class ReadMemory(Record):
    """Explicit guarded read from a versioned location into an SSE value."""

    state: MemoryVersionId
    location: MemoryLocationId
    result: SymbolicExprId
    guard: SymbolicExprId | None
    origin: str

    def __post_init__(self):
        super().__post_init__()
        same_scope(self.state.scope, self.location, self.result, self.guard)
        key(self.origin)


class SymbolicOp(str, Enum):
    """Pure scalar operations plus explicit memory-read and unknown leaves."""

    SYMBOL = 'symbol'
    CONSTANT = 'constant'
    ADD = 'add'
    COPY = 'copy'
    SUB = 'sub'
    MUL = 'mul'
    AND = 'and_bits'
    OR = 'or_bits'
    XOR = 'xor_bits'
    ULT = 'ult'
    SLT = 'slt'
    EXTRACT = 'extract'
    ZERO_EXTEND = 'zero_extend'
    SIGN_EXTEND = 'sign_extend'
    CONCAT = 'concat'
    IF = 'if'
    NOT = 'not'
    EQ = 'eq'
    MEMORY_READ = 'memory_read'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class SymbolicNode(Record):
    """Typed, scoped SSE DAG node with no implicit memory operation."""

    id: SymbolicExprId
    type: ValueType
    op: SymbolicOp
    operands: tuple[SymbolicExprId, ...]
    origin: str
    value: int | bool | str | None = None
    state: MemoryVersionId | None = None
    location: MemoryLocationId | None = None
    params: tuple[int, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        same_scope(self.id.scope, *self.operands, self.state, self.location)
        leaf = self.op in (SymbolicOp.SYMBOL, SymbolicOp.CONSTANT, SymbolicOp.MEMORY_READ, SymbolicOp.UNKNOWN)
        if leaf and (self.operands or self.params):
            raise ValueError('Symbolic leaf cannot contain hidden operations')
        if self.op == SymbolicOp.CONSTANT:
            Constant(self.value, self.type)
        elif self.op in (SymbolicOp.SYMBOL, SymbolicOp.UNKNOWN):
            text(self.value, 'symbol name / unknown reason')
        elif self.value is not None:
            raise ValueError('Only constant/symbol/unknown nodes carry a literal')
        if (self.op == SymbolicOp.MEMORY_READ) != (self.state is not None and self.location is not None):
            raise ValueError('MemoryRead requires both memory version and location')
        if self.op != SymbolicOp.MEMORY_READ and (self.state is not None or self.location is not None):
            raise ValueError('Pure symbolic value cannot carry an implicit memory operation')


@dataclass(frozen=True)
class TaintFact(Record):
    """Traceable taint fact tied to context, guard, path/APG, and memory state."""

    id: str
    root: AccessRoot
    path: AccessPathId | None
    graph: AccessGraphId | None
    context: ContextId
    memory_version: MemoryVersionId
    guard: SymbolicExprId | None
    taint_kind: str
    origin: str
    provenance: tuple[str, ...]
    assessment: Assessment = Assessment()

    def __post_init__(self):
        super().__post_init__()
        key(self.id)
        key(self.origin)
        text(self.taint_kind, 'taint kind')
        if (self.path is None) == (self.graph is None):
            raise ValueError('Taint fact needs exactly one path or APG reference')
        same_scope(self.memory_version.scope, self.path, self.graph, self.guard)
        if self.context != self.memory_version.scope.context or not self.provenance:
            raise ValueError('Taint context/provenance is missing or inconsistent')


DefinitionId = SymbolicExprId | MemoryVersionId


def acyclic(dependencies: Mapping[DefinitionId, set[DefinitionId]]) -> None:
    """Check descriptor definitions only; this is not dataflow convergence."""
    pending = {node: set(deps) for node, deps in dependencies.items()}
    if any(not deps <= pending.keys() for deps in pending.values()):
        raise ValueError('Dangling symbolic/memory definition reference')
    reverse = {node: set() for node in pending}
    for node, deps in pending.items():
        for dep in deps:
            reverse[dep].add(node)
    ready = [node for node, deps in pending.items() if not deps]
    visited = 0
    while ready:
        node = ready.pop()
        visited += 1
        for successor in reverse[node]:
            pending[successor].remove(node)
            if not pending[successor]:
                ready.append(successor)
    if visited != len(pending):
        raise ValueError('Cyclic SSE/MemoryVersion definitions require an explicit future summary semantics')


@dataclass(frozen=True)
class MemorySnapshot(Record):
    """Validated wire snapshot of memory, SSE, alias, and taint descriptors."""

    scope: AnalysisScope
    architecture: Architecture
    origin_map: tuple[Origin, ...]
    objects: tuple[MemoryObject, ...] = ()
    paths: tuple[AccessPath, ...] = ()
    graphs: tuple[AccessGraph, ...] = ()
    locations: tuple[MemoryLocation, ...] = ()
    versions: tuple[MemoryVersion, ...] = ()
    reads: tuple[ReadMemory, ...] = ()
    expressions: tuple[SymbolicNode, ...] = ()
    taint_facts: tuple[TaintFact, ...] = ()
    assessment: Assessment = Assessment()
    object_facts: tuple[HeapObject, ...] = ()
    cells: tuple[HeapCell, ...] = ()
    budgets: SemanticBudgets = SemanticBudgets()
    schema_version: str = 'Memory-Semantics-v1'

    def __post_init__(self):
        super().__post_init__()
        if self.schema_version != 'Memory-Semantics-v1' or self.architecture.byte_bits != 8:
            raise ValueError('Unsupported memory schema / non-octet architecture')
        origins = {o.id: o for o in self.origin_map}
        if len(origins) != len(self.origin_map) or any(o.point.function != self.scope.function for o in self.origin_map):
            raise ValueError('Duplicate or foreign memory origin')
        def origin(value):
            if value not in origins:
                raise ValueError('Undeclared memory origin: ' + value)
        def index(records):
            result = {record.id: record for record in records}
            if len(result) != len(records):
                raise ValueError('Duplicate memory descriptor ID')
            return result
        objects, paths, graphs, locations, versions, exprs = map(index,
            (self.objects, self.paths, self.graphs, self.locations, self.versions, self.expressions))
        object_facts = {item.object_id: item for item in self.object_facts}
        if len(object_facts) != len(self.object_facts) or not object_facts.keys() <= objects.keys():
            raise ValueError('Duplicate or dangling heap object facts')
        for item in self.object_facts:
            if item.allocation_origin is not None:
                origin(item.allocation_origin)
        if any(obj.id.binary != self.scope.function.binary for obj in self.objects):
            raise ValueError('Object descriptor belongs to another image')
        def root(value):
            origin(value.origin)
            if value.object_id not in objects:
                raise ValueError('Undeclared root object')
            if value.address_space != objects[value.object_id].address_space:
                raise ValueError('Root/object address spaces differ')
        for record in self.paths + self.graphs + self.locations + self.versions + self.expressions:
            same_scope(self.scope, record.id)
        def segment(value):
            if isinstance(value, Index) and value.expression not in exprs:
                raise ValueError('Dangling index expression')
            if isinstance(value, Index) and exprs[value.expression].type.kind != TypeKind.BV:
                raise ValueError('Index requires a bitvector expression')
            if isinstance(value, Deref) and value.pointer_bits != self.architecture.pointer_bits:
                raise ValueError('Deref pointer width differs from the architecture')
        for path in self.paths:
            origin(path.origin)
            root(path.root)
            for item in path.segments:
                segment(item)
        for graph in self.graphs:
            for node in graph.nodes:
                if node.root is not None:
                    root(node.root)
            for edge in graph.edges:
                segment(edge.label)
            for summary in graph.summaries:
                if summary.trigger.function != self.scope.function:
                    raise ValueError('Summary trigger belongs to another function')
                for item in summary.pattern:
                    segment(item)
        for location in self.locations:
            origin(location.origin)
            if location.object_id is not None and location.object_id not in objects:
                raise ValueError('Undeclared location object')
            if location.object_id is not None and location.address_space != objects[location.object_id].address_space:
                raise ValueError('Location/object address spaces differ')
        def guard(reference):
            if reference is not None and (reference not in exprs or exprs[reference].type.kind != TypeKind.BOOL):
                raise ValueError('Memory guard must reference a declared boolean expression')
        dependencies = {}
        for expression in self.expressions:
            origin(expression.origin)
            dependencies[expression.id] = set(expression.operands)
            if expression.op == SymbolicOp.MEMORY_READ:
                if expression.location not in locations or expression.state not in versions:
                    raise ValueError('Dangling MemoryRead state/location')
                if expression.type.bits != locations[expression.location].width_bits:
                    raise ValueError('MemoryRead value/location width mismatch')
                dependencies[expression.id].add(expression.state)
            if any(operand not in exprs for operand in expression.operands):
                raise ValueError('Dangling SSE operand')
            if expression.op not in (SymbolicOp.SYMBOL, SymbolicOp.CONSTANT, SymbolicOp.MEMORY_READ, SymbolicOp.UNKNOWN):
                validate_value_operation(expression.op.value, expression.type,
                    [exprs[operand].type for operand in expression.operands], expression.params)
        for version in self.versions:
            definition = version.definition
            origin(definition.origin)
            dependencies[version.id] = set(version.parents)
            if isinstance(definition, WriteMemory):
                if definition.location not in locations or definition.value not in exprs:
                    raise ValueError('Dangling write value/location')
                if locations[definition.location].width_bits != exprs[definition.value].type.bits:
                    raise ValueError('Write value/location width mismatch')
                if definition.update == UpdateKind.STRONG:
                    location = locations[definition.location]
                    fact = object_facts.get(location.object_id)
                    if (location.object_id is None or location.offset_lower is None
                            or location.offset_lower != location.offset_upper or fact is None
                            or fact.cardinality != ObjectCardinality.SINGLETON):
                        raise ValueError('Strong update requires an exact location and singleton object evidence')
                guard(definition.guard)
                dependencies[version.id].add(definition.value)
                if definition.guard is not None:
                    dependencies[version.id].add(definition.guard)
            if isinstance(definition, JoinMemory):
                for item in definition.inputs:
                    guard(item.guard)
                    if item.guard is not None:
                        dependencies[version.id].add(item.guard)
            if isinstance(definition, HavocMemory):
                guard(definition.guard)
                if definition.guard is not None:
                    dependencies[version.id].add(definition.guard)
        acyclic(dependencies)
        cell_keys = {(cell.location, cell.defined_in) for cell in self.cells}
        if len(cell_keys) != len(self.cells):
            raise ValueError('Duplicate heap cell/version binding')
        for cell in self.cells:
            origin(cell.origin)
            same_scope(self.scope, cell.location, cell.value, cell.defined_in)
            if cell.location not in locations or cell.value not in exprs or cell.defined_in not in versions:
                raise ValueError('Dangling heap cell binding')
            if locations[cell.location].width_bits != exprs[cell.value].type.bits:
                raise ValueError('Heap cell value/location width mismatch')
        for read in self.reads:
            origin(read.origin)
            same_scope(self.scope, read.state, read.location, read.result, read.guard)
            guard(read.guard)
            if read.result not in exprs or read.state not in versions or read.location not in locations:
                raise ValueError('Dangling explicit read')
            result = exprs[read.result]
            if result.op != SymbolicOp.MEMORY_READ or (result.state, result.location) != (read.state, read.location):
                raise ValueError('Read descriptor and SSE MemoryRead disagree')
        if len({fact.id for fact in self.taint_facts}) != len(self.taint_facts):
            raise ValueError('Duplicate taint fact ID')
        for fact in self.taint_facts:
            origin(fact.origin)
            root(fact.root)
            same_scope(self.scope, fact.memory_version, fact.guard, fact.path, fact.graph)
            guard(fact.guard)
            if fact.memory_version not in versions or (fact.path is not None and fact.path not in paths) or (fact.graph is not None and fact.graph not in graphs):
                raise ValueError('Dangling taint path/graph/state')
            if fact.path is not None and paths[fact.path].root != fact.root:
                raise ValueError('Taint fact root differs from its path root')
            if fact.graph is not None:
                graph = graphs[fact.graph]
                roots = {node.root for node in graph.nodes if node.id in graph.entries and node.root is not None}
                if fact.root not in roots:
                    raise ValueError('Taint fact root differs from the APG entry roots')
        if self.assessment.status == Completeness.COMPLETE:
            nested = [r.assessment for r in self.paths + self.graphs + self.locations + self.taint_facts]
            nested.extend(cell.assessment for cell in self.cells)
            nested.extend(v.definition.alias.assessment for v in self.versions if isinstance(v.definition, WriteMemory))
            if any(a.status != Completeness.COMPLETE for a in nested) or any(e.op == SymbolicOp.UNKNOWN for e in self.expressions):
                raise ValueError('Incomplete memory descriptors cannot yield a complete snapshot')
            if any(isinstance(v.definition, HavocMemory) for v in self.versions):
                raise ValueError('Unknown external havoc must retain an incomplete snapshot assessment')
