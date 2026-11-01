"""Backend-free P2 identities. Addresses in IDs are image-relative (RVA)."""
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re


def integer(value, name, minimum=0):
    if type(value) is not int:
        raise TypeError(name + ' must be an integer')
    if minimum is not None and value < minimum:
        raise ValueError(name + ' is below its minimum')


def text(value, name, allow_empty=False):
    if type(value) is not str:
        raise TypeError(name + ' must be text')
    if not allow_empty and not value:
        raise ValueError(name + ' must not be empty')


def typed(value, kind, name):
    if not isinstance(value, kind):
        raise TypeError(name + ' must be ' + kind.__name__)


def tuple_of(value, kind, name):
    if type(value) is not tuple:
        raise TypeError(name + ' must be an immutable tuple')
    for item in value:
        typed(item, kind, name + ' item')


class StableIdentity:
    @property
    def token(self):
        # Public identity is a deterministic digest, never Python's salted hash.
        payload = {'type': type(self).__name__, 'fields': asdict(self)}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class BinaryId(StableIdentity):
    sha256: str

    def __post_init__(self):
        text(self.sha256, 'binary SHA256')
        if not re.fullmatch('[0-9a-f]{64}', self.sha256):
            raise ValueError('BinaryId requires a lowercase SHA256 of the image bytes')

    @classmethod
    def from_bytes(cls, data):
        if type(data) is not bytes:
            raise TypeError('Binary bytes required')
        return cls(hashlib.sha256(data).hexdigest())


@dataclass(frozen=True)
class FunctionId(StableIdentity):
    binary: BinaryId
    rva: int

    def __post_init__(self):
        typed(self.binary, BinaryId, 'function binary')
        integer(self.rva, 'function RVA')


@dataclass(frozen=True)
class BlockId(StableIdentity):
    function: FunctionId
    rva: int
    index: int = 0
    mode: str = 'default'

    def __post_init__(self):
        typed(self.function, FunctionId, 'block function')
        integer(self.rva, 'block RVA')
        integer(self.index, 'block variant index')
        text(self.mode, 'instruction mode')


@dataclass(frozen=True)
class ProgramPoint(StableIdentity):
    block: BlockId
    statement: int | None = None
    instruction_rva: int | None = None

    def __post_init__(self):
        typed(self.block, BlockId, 'point block')
        if self.statement is not None:
            integer(self.statement, 'statement index')
        if self.instruction_rva is not None:
            integer(self.instruction_rva, 'instruction RVA')

    @property
    def function(self):
        return self.block.function


@dataclass(frozen=True)
class CallSiteId(StableIdentity):
    point: ProgramPoint
    ordinal: int = 0

    def __post_init__(self):
        typed(self.point, ProgramPoint, 'call point')
        integer(self.ordinal, 'call ordinal')

    @property
    def function(self):
        return self.point.function


@dataclass(frozen=True)
class ContextId(StableIdentity):
    call_string: tuple[CallSiteId, ...] = ()
    abstraction: str = 'exact'

    def __post_init__(self):
        tuple_of(self.call_string, CallSiteId, 'call string')
        text(self.abstraction, 'context abstraction')
        # Context abstraction is explicit metadata. P2 never truncates a string.


class MemoryKind(str, Enum):
    STACK = 'stack'
    GLOBAL = 'global'
    HEAP = 'heap'
    ARGUMENT = 'argument'
    RETURN = 'return'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class MemoryObjectId(StableIdentity):
    """Abstract object identity only; distinct IDs do not establish NoAlias.

    Heap defaults to allocation-site/context abstraction, not concrete allocation
    identity. Frame/instance discrimination must be supplied by the analysis.
    """
    kind: MemoryKind
    binary: BinaryId
    function: FunctionId | None
    context: ContextId | None
    site: ProgramPoint | None
    coordinates: tuple

    def __post_init__(self):
        typed(self.kind, MemoryKind, 'memory kind')
        typed(self.binary, BinaryId, 'object binary')
        if self.function is not None:
            typed(self.function, FunctionId, 'object function')
            if self.function.binary != self.binary:
                raise ValueError('Object function belongs to another image')
        if self.context is not None:
            typed(self.context, ContextId, 'object context')
        if self.site is not None:
            typed(self.site, ProgramPoint, 'allocation site')
            if self.site.function != self.function:
                raise ValueError('Allocation site/function mismatch')
        if type(self.coordinates) is not tuple:
            raise TypeError('Object coordinates must be a tuple')
        expected = {
            MemoryKind.STACK: (str, int), MemoryKind.GLOBAL: (str, int),
            MemoryKind.HEAP: (str,), MemoryKind.ARGUMENT: (int,),
            MemoryKind.RETURN: (int,), MemoryKind.UNKNOWN: (str, str, str),
        }[self.kind]
        if len(self.coordinates) != len(expected) or any(type(v) is not t for v, t in zip(self.coordinates, expected)):
            raise TypeError('Invalid coordinates for memory kind ' + self.kind.value)
        for value in self.coordinates:
            if isinstance(value, str):
                text(value, 'object coordinate')
        scoped = self.kind in (MemoryKind.STACK, MemoryKind.HEAP, MemoryKind.ARGUMENT, MemoryKind.RETURN)
        if scoped != (self.function is not None):
            raise ValueError('Invalid function scope for memory kind')
        if scoped and self.context is None:
            raise ValueError('Scoped objects require explicit context')
        if (self.kind == MemoryKind.HEAP) != (self.site is not None):
            raise ValueError('Only heap identities require an allocation point')
        if self.kind == MemoryKind.GLOBAL and self.context is not None:
            raise ValueError('Global identities are independent of call context')
        if self.kind in (MemoryKind.ARGUMENT, MemoryKind.RETURN):
            integer(self.coordinates[0], 'interface index')
        if self.kind == MemoryKind.GLOBAL:
            integer(self.coordinates[1], 'global RVA')

    @classmethod
    def stack(cls, function, context, frame_id, offset=0):
        return cls(MemoryKind.STACK, function.binary, function, context, None, (frame_id, offset))

    @classmethod
    def global_object(cls, binary, region, rva):
        return cls(MemoryKind.GLOBAL, binary, None, None, None, (region, rva))

    @classmethod
    def heap(cls, site, context, instance='allocation-site-summary'):
        return cls(MemoryKind.HEAP, site.function.binary, site.function, context, site, (instance,))

    @classmethod
    def argument(cls, function, index, context):
        return cls(MemoryKind.ARGUMENT, function.binary, function, context, None, (index,))

    @classmethod
    def return_value(cls, function, context, index=0):
        return cls(MemoryKind.RETURN, function.binary, function, context, None, (index,))

    @classmethod
    def unknown(cls, binary, region, reason, origin_key, context=None):
        return cls(MemoryKind.UNKNOWN, binary, None, context, None, (region, reason, origin_key))
