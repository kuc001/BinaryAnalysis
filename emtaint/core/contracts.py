"""Shared P3 descriptors and scoped references, not an execution engine."""
from dataclasses import dataclass, fields
from enum import Enum
from functools import lru_cache
import types
from typing import get_args, get_origin, get_type_hints, Union

from .identity import FunctionId, ProgramPoint, ContextId, StableIdentity, integer, text
from .program import Completeness

CIR_VERSION = 'CIR-Wire-v1'
MEMORY_VERSION = 'Memory-Semantics-v1'


class UnsupportedSemantics(NotImplementedError):
    """A missing semantic implementation must never be interpreted as no effect."""


def check_type(value, annotation):
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in (Union, types.UnionType):
        return any(check_type(value, kind) for kind in args)
    if annotation is type(None):
        return value is None
    if annotation in (str, int, bool):
        return type(value) is annotation
    if origin is tuple or annotation is tuple:
        if type(value) is not tuple:
            return False
        if not args:
            return True
        if len(args) == 2 and args[1] is Ellipsis:
            return all(check_type(v, args[0]) for v in value)
        return len(value) == len(args) and all(check_type(v, a) for v, a in zip(value, args))
    return isinstance(annotation, type) and isinstance(value, annotation)


@lru_cache(maxsize=512)
def record_annotations(cls):
    """Immutable class metadata only; no session/analysis objects are cached."""
    return types.MappingProxyType(get_type_hints(cls))


class Record:
    """Validate immutable, explicitly typed fields for every P3 DTO constructor."""
    def __post_init__(self):
        hints = record_annotations(type(self))
        for field in fields(self):
            if not check_type(getattr(self, field.name), hints[field.name]):
                raise TypeError(type(self).__name__ + '.' + field.name + ' has an invalid type')


def key(value):
    text(value, 'reference key')
    if len(value) > 256:
        raise ValueError('Reference key exceeds 256 characters')


def bits(value, byte_access=False):
    integer(value, 'bit width', 1)
    if value > 4096 or (byte_access and value % 8):
        raise ValueError('Unsupported bit width (memory v1 uses whole 8-bit bytes)')


class Precision(str, Enum):
    EXACT = 'exact'
    OVER_APPROX = 'over_approx'
    INCOMPLETE = 'incomplete'


@dataclass(frozen=True)
class Assessment(Record):
    status: Completeness = Completeness.INCOMPLETE
    precision: Precision = Precision.INCOMPLETE
    precision_loss: tuple[str, ...] = ()
    unsupported_ops: tuple[str, ...] = ()
    diagnostics: tuple[str, ...] = ('Semantic execution not performed',)

    def __post_init__(self):
        super().__post_init__()
        if self.precision == Precision.EXACT and self.precision_loss:
            raise ValueError('Exact results cannot discard precision')
        if self.status == Completeness.COMPLETE and (self.unsupported_ops or self.precision == Precision.INCOMPLETE):
            raise ValueError('Incomplete/unsupported semantics cannot be marked complete')
        if self.status != Completeness.COMPLETE and not (self.diagnostics or self.unsupported_ops):
            raise ValueError('Incomplete/unknown assessment requires diagnostics')

    @classmethod
    def complete(cls):
        return cls(Completeness.COMPLETE, Precision.EXACT, diagnostics=())


@dataclass(frozen=True)
class Producer(Record):
    name: str
    version: str
    frontend: str

    def __post_init__(self):
        super().__post_init__()
        for value in (self.name, self.version, self.frontend):
            text(value, 'producer metadata')


@dataclass(frozen=True)
class Origin(Record):
    id: str
    point: ProgramPoint
    producer: Producer
    source_opcode: str

    def __post_init__(self):
        super().__post_init__()
        key(self.id)
        text(self.source_opcode, 'source opcode')


class TypeKind(str, Enum):
    BOOL = 'bool'
    BV = 'bitvector'
    POINTER = 'pointer'


class Signedness(str, Enum):
    UNSIGNED = 'unsigned'
    SIGNED = 'signed'
    UNSPECIFIED = 'unspecified'


@dataclass(frozen=True)
class ValueType(Record):
    kind: TypeKind
    bits: int
    signedness: Signedness = Signedness.UNSPECIFIED
    address_space: str | None = None

    def __post_init__(self):
        super().__post_init__()
        bits(self.bits)
        if self.kind == TypeKind.BOOL and (self.bits != 1 or self.signedness != Signedness.UNSPECIFIED):
            raise ValueError('Boolean type is one bit with no signed interpretation')
        if (self.kind == TypeKind.POINTER) != (self.address_space is not None):
            raise ValueError('Only pointer types carry an address space')
        if self.address_space is not None:
            text(self.address_space, 'pointer address space')

    @classmethod
    def boolean(cls):
        return cls(TypeKind.BOOL, 1)

    @classmethod
    def bv(cls, width, signedness=Signedness.UNSPECIFIED):
        return cls(TypeKind.BV, width, signedness)

    @classmethod
    def pointer(cls, width, address_space='default'):
        return cls(TypeKind.POINTER, width, Signedness.UNSIGNED, address_space)


@dataclass(frozen=True)
class ValueRef(Record):
    id: str
    type: ValueType

    def __post_init__(self):
        super().__post_init__()
        key(self.id)


@dataclass(frozen=True)
class Constant(Record):
    value: int | bool
    type: ValueType

    def __post_init__(self):
        super().__post_init__()
        if self.type.kind == TypeKind.BOOL:
            if type(self.value) is not bool:
                raise TypeError('Boolean constant needs a bool, not an integer')
        elif type(self.value) is not int or not 0 <= self.value < (1 << self.type.bits):
            raise ValueError('BV/pointer constants must be explicitly truncated to their width')


Operand = ValueRef | Constant


def boolean(value):
    if not check_type(value, Operand) or value.type.kind != TypeKind.BOOL:
        raise ValueError('Guard must be an explicitly typed boolean')


def validate_value_operation(op, result, types, params=()):
    """Shared CIR/SSE scalar typing rules; no evaluation or AST construction."""
    if op in ('add', 'sub', 'mul', 'and_bits', 'or_bits', 'xor_bits'):
        ordinary = len(types) == 2 and types == [result, result] and result.kind == TypeKind.BV
        pointer = (op in ('add', 'sub') and len(types) == 2 and types[0] == result
                   and result.kind == TypeKind.POINTER and types[1].kind == TypeKind.BV
                   and types[1].bits == result.bits)
        difference = (op == 'sub' and len(types) == 2 and types[0] == types[1]
                      and types[0].kind == TypeKind.POINTER and result.kind == TypeKind.BV
                      and result.bits == types[0].bits)
        valid = ordinary or pointer or difference
    elif op == 'copy':
        valid = types == [result]
    elif op in ('eq', 'ult', 'slt'):
        valid = (len(types) == 2 and types[0] == types[1] and result == ValueType.boolean()
                 and (op == 'eq' or types[0].kind != TypeKind.BOOL))
    elif op == 'not':
        valid = types == [ValueType.boolean()] and result == ValueType.boolean()
    elif op == 'if':
        valid = types == [ValueType.boolean(), result, result]
    elif op == 'extract':
        valid = (len(types) == 1 and types[0].kind == result.kind == TypeKind.BV and len(params) == 2
                 and 0 <= params[1] <= params[0] < types[0].bits and result.bits == params[0] - params[1] + 1)
    elif op in ('zero_extend', 'sign_extend'):
        valid = (len(types) == 1 and types[0].kind == result.kind == TypeKind.BV and len(params) == 1
                 and params[0] >= 0 and result.bits == types[0].bits + params[0])
    elif op == 'concat':
        valid = (len(types) >= 2 and result.kind == TypeKind.BV
                 and all(t.kind == TypeKind.BV for t in types) and result.bits == sum(t.bits for t in types))
    else:
        raise ValueError('Unsupported scalar operation: ' + op)
    if not valid or (params and op not in ('extract', 'zero_extend', 'sign_extend')):
        raise ValueError('Invalid typed computation: ' + op)


@dataclass(frozen=True)
class AnalysisScope(Record, StableIdentity):
    function: FunctionId
    context: ContextId
    session_id: str
    cfg_version: int
    cg_version: int
    state_revision: int = 0

    def __hash__(self):
        # Implementation memo only: fields/wire identity remain unchanged.
        value=getattr(self,'_stable_hash',None)
        if value is None:
            value=hash((self.function,self.context,self.session_id,self.cfg_version,self.cg_version,self.state_revision))
            object.__setattr__(self,'_stable_hash',value)
        return value

    def __reduce__(self):
        # Python hash randomization differs between processes. Reconstruct
        # from semantic fields so a cached hash is never persisted by pickle.
        return type(self),(self.function,self.context,self.session_id,self.cfg_version,self.cg_version,self.state_revision)

    def __post_init__(self):
        super().__post_init__()
        key(self.session_id)
        integer(self.cfg_version, 'CFG version')
        integer(self.cg_version, 'CG version')
        integer(self.state_revision, 'session state revision')
        if any(site.function.binary != self.function.binary for site in self.context.call_string):
            raise ValueError('Single-image analysis scope contains a foreign callsite')

    @classmethod
    def from_session(cls, session, function, context):
        from .session import AnalysisSession
        if not isinstance(session, AnalysisSession):
            raise TypeError('AnalysisSession required')
        session.program.function(function)
        session.register_context(context)
        return cls(function, context, session.stamp.session_id, session.cfg_version(function),
                   session.cg_version, session.stamp.state_revision)

    def assert_current(self, session):
        if self != type(self).from_session(session, self.function, self.context):
            raise ValueError('Stale or foreign analysis scope; graph/state revisions changed')


@dataclass(frozen=True)
class ScopedId(Record, StableIdentity):
    scope: AnalysisScope
    key: str

    def __post_init__(self):
        super().__post_init__()
        key(self.key)


@dataclass(frozen=True)
class SymbolicExprId(ScopedId):
    pass


@dataclass(frozen=True)
class MemoryVersionId(ScopedId):
    pass


@dataclass(frozen=True)
class AccessPathId(ScopedId):
    pass


@dataclass(frozen=True)
class AccessGraphId(ScopedId):
    pass


@dataclass(frozen=True)
class MemoryLocationId(ScopedId):
    pass


def same_scope(scope, *references):
    if any(ref is not None and ref.scope != scope for ref in references):
        raise ValueError('Cross-session/context/graph-version reference')


@dataclass(frozen=True)
class SemanticBudgets(Record):
    apg_nodes: int = 10000
    apg_edges: int = 20000
    apg_summaries: int = 1000
    sse_nodes: int = 100000
    heap_objects: int = 10000
    heap_cells: int = 100000
    worklist_states: int = 100000
    worklist_iterations: int = 1000000
    contexts: int = 10000
    alias_candidates: int = 1000
    solver_queries: int = 1000
    solver_timeout_ms: int = 1000

    def __post_init__(self):
        super().__post_init__()
        for name, value in vars(self).items():
            integer(value, name, 1)

    def exhausted(self, dimension):
        if dimension not in vars(self):
            raise ValueError('Unknown semantic budget dimension')
        return Assessment(diagnostics=('Budget exhausted: ' + dimension + '; no absence-of-facts conclusion',))
