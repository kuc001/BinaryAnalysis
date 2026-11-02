"""Backend-free P2 identities. Addresses in IDs are image-relative (RVA)."""
from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Self, TypeVar


T = TypeVar('T')


def integer(value: object, name: str, minimum: int | None = 0) -> None:
    """Require an exact integer at or above an optional inclusive minimum."""

    if type(value) is not int:
        raise TypeError(name + ' must be an integer')
    if minimum is not None and value < minimum:
        raise ValueError(name + ' is below its minimum')


def text(value: object, name: str, allow_empty: bool = False) -> None:
    """Require text and reject empty values unless the contract permits them."""

    if type(value) is not str:
        raise TypeError(name + ' must be text')
    if not allow_empty and not value:
        raise ValueError(name + ' must not be empty')


def typed(value: object, kind: type[T], name: str) -> None:
    """Require ``value`` to satisfy a concrete runtime class contract."""

    if not isinstance(value, kind):
        raise TypeError(name + ' must be ' + kind.__name__)


def tuple_of(value: object, kind: type[T], name: str) -> None:
    """Require an immutable tuple whose members all have ``kind``."""

    if type(value) is not tuple:
        raise TypeError(name + ' must be an immutable tuple')
    for item in value:
        typed(item, kind, name + ' item')


class StableIdentity:
    """Mixin for deterministic identities independent of Python hash seeding."""

    @property
    def token(self) -> str:
        """Return the SHA-256 token of the identity type and semantic fields."""

        # Public identity is a deterministic digest, never Python's salted hash.
        payload = {'type': type(self).__name__, 'fields': asdict(self)}
        return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


@dataclass(frozen=True)
class BinaryId(StableIdentity):
    """Identity of one binary image by lowercase SHA-256 digest."""

    sha256: str

    def __post_init__(self):
        text(self.sha256, 'binary SHA256')
        if not re.fullmatch('[0-9a-f]{64}', self.sha256):
            raise ValueError('BinaryId requires a lowercase SHA256 of the image bytes')

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """Construct an image identity from its exact byte content."""

        if type(data) is not bytes:
            raise TypeError('Binary bytes required')
        return cls(hashlib.sha256(data).hexdigest())


@dataclass(frozen=True)
class FunctionId(StableIdentity):
    """Function identity scoped to a binary and image-relative address."""

    binary: BinaryId
    rva: int

    def __post_init__(self):
        typed(self.binary, BinaryId, 'function binary')
        integer(self.rva, 'function RVA')


@dataclass(frozen=True)
class BlockId(StableIdentity):
    """Basic-block identity including RVA, decoding mode, and variant index."""

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
    """Optional statement/instruction position within a declared basic block."""

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
    def function(self) -> FunctionId:
        """Return the function that owns this program point."""

        return self.block.function


@dataclass(frozen=True)
class CallSiteId(StableIdentity):
    """Call occurrence at a program point, disambiguated by ordinal."""

    point: ProgramPoint
    ordinal: int = 0

    def __post_init__(self):
        typed(self.point, ProgramPoint, 'call point')
        integer(self.ordinal, 'call ordinal')

    @property
    def function(self) -> FunctionId:
        """Return the function that contains this call site."""

        return self.point.function


@dataclass(frozen=True)
class ContextId(StableIdentity):
    """Explicit call-string context and its abstraction policy."""

    call_string: tuple[CallSiteId, ...] = ()
    abstraction: str = 'exact'

    def __post_init__(self):
        tuple_of(self.call_string, CallSiteId, 'call string')
        text(self.abstraction, 'context abstraction')
        # Context abstraction is explicit metadata. P2 never truncates a string.


class MemoryKind(str, Enum):
    """Supported abstract memory-object ownership categories."""

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
    coordinates: tuple[str | int, ...]

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
    def stack(
        cls, function: FunctionId, context: ContextId, frame_id: str, offset: int = 0
    ) -> Self:
        """Create a stack object keyed by function, context, frame, and offset."""

        return cls(MemoryKind.STACK, function.binary, function, context, None, (frame_id, offset))

    @classmethod
    def global_object(cls, binary: BinaryId, region: str, rva: int) -> Self:
        """Create a context-independent global object at an image RVA."""

        return cls(MemoryKind.GLOBAL, binary, None, None, None, (region, rva))

    @classmethod
    def heap(
        cls,
        site: ProgramPoint,
        context: ContextId,
        instance: str = 'allocation-site-summary',
    ) -> Self:
        """Create a heap object using allocation site and context abstraction."""

        return cls(MemoryKind.HEAP, site.function.binary, site.function, context, site, (instance,))

    @classmethod
    def argument(cls, function: FunctionId, index: int, context: ContextId) -> Self:
        """Create the abstract object representing a function argument."""

        return cls(MemoryKind.ARGUMENT, function.binary, function, context, None, (index,))

    @classmethod
    def return_value(
        cls, function: FunctionId, context: ContextId, index: int = 0
    ) -> Self:
        """Create the abstract object representing a function return slot."""

        return cls(MemoryKind.RETURN, function.binary, function, context, None, (index,))

    @classmethod
    def unknown(
        cls,
        binary: BinaryId,
        region: str,
        reason: str,
        origin_key: str,
        context: ContextId | None = None,
    ) -> Self:
        """Create an explicit unknown object without inventing alias precision."""

        return cls(MemoryKind.UNKNOWN, binary, None, context, None, (region, reason, origin_key))
