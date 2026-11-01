"""P3 heap-state descriptors and port, not a heap read/write implementation."""
from dataclasses import dataclass
from enum import Enum
from typing import Protocol, TYPE_CHECKING

from emtaint.core import MemoryObjectId
from emtaint.core.contracts import (Record, Assessment, MemoryVersionId, MemoryLocationId,
    SymbolicExprId, UnsupportedSemantics, same_scope, key)
from emtaint.core.identity import text

if TYPE_CHECKING:
    from .state import MemorySnapshot


class ObjectCardinality(str, Enum):
    SINGLETON = 'singleton'
    SUMMARY = 'summary'
    UNKNOWN = 'unknown'


class ObjectLifetime(str, Enum):
    STATIC = 'static'
    FRAME = 'stack_frame'
    ALLOCATED = 'allocated'
    EXTERNAL = 'external'
    FREED = 'freed'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class HeapObject(Record):
    object_id: MemoryObjectId
    region: str
    cardinality: ObjectCardinality
    lifetime: ObjectLifetime
    allocation_origin: str | None
    provenance: tuple[str, ...]

    def __post_init__(self):
        super().__post_init__()
        text(self.region, 'heap object region')
        if self.allocation_origin is not None:
            key(self.allocation_origin)
        if not self.provenance or any(not item for item in self.provenance):
            raise ValueError('Object cardinality/lifetime claims require provenance')


@dataclass(frozen=True)
class HeapCell(Record):
    location: MemoryLocationId
    value: SymbolicExprId
    defined_in: MemoryVersionId
    origin: str
    assessment: Assessment = Assessment()

    def __post_init__(self):
        super().__post_init__()
        same_scope(self.defined_in.scope, self.location, self.value)
        key(self.origin)


class AbstractHeap(Protocol):
    def snapshot(self, state: MemoryVersionId) -> 'MemorySnapshot': ...
    def object_info(self, object_id: MemoryObjectId) -> HeapObject: ...


class UnimplementedAbstractHeap:
    def snapshot(self, state):
        raise UnsupportedSemantics('AbstractHeap snapshots require the P5 engine')

    def object_info(self, object_id):
        raise UnsupportedSemantics('Object lifetime/cardinality analysis requires P5')
