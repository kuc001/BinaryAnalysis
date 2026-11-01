"""P3 semantic port declarations. P5 must supply executable heap operations."""
from dataclasses import dataclass
from typing import Protocol

from emtaint.core import MemoryObjectId
from emtaint.core.contracts import (Record, Assessment, SymbolicExprId, MemoryVersionId,
    UnsupportedSemantics, same_scope)
from emtaint.core.identity import integer
from .state import (MemoryLocation, ReadMemory, WriteMemory, MemoryVersion, AliasResult)


@dataclass(frozen=True)
class QueryBudget(Record):
    max_steps: int = 10000
    max_alias_candidates: int = 1000
    max_solver_queries: int = 100
    timeout_ms: int = 1000

    def __post_init__(self):
        super().__post_init__()
        for name, value in vars(self).items():
            integer(value, name, 1)


@dataclass(frozen=True)
class ReadResult(Record):
    value: SymbolicExprId
    state: MemoryVersionId
    assessment: Assessment

    def __post_init__(self):
        super().__post_init__()
        same_scope(self.state.scope, self.value)


@dataclass(frozen=True)
class WriteResult(Record):
    state: MemoryVersionId
    assessment: Assessment


@dataclass(frozen=True)
class PointsToResult(Record):
    candidates: tuple[MemoryObjectId, ...]
    assessment: Assessment


@dataclass(frozen=True)
class DefinitionResult(Record):
    definitions: tuple[MemoryVersionId, ...]
    assessment: Assessment


class MemoryQueryPort(Protocol):
    def read(self, request: ReadMemory, budget: QueryBudget) -> ReadResult: ...
    def write(self, request: WriteMemory, budget: QueryBudget) -> WriteResult: ...
    def resolve_alias(self, state: MemoryVersionId, left: MemoryLocation, right: MemoryLocation,
                      budget: QueryBudget) -> AliasResult: ...
    def points_to(self, state: MemoryVersionId, address: SymbolicExprId,
                  budget: QueryBudget) -> PointsToResult: ...
    def resolve_definition(self, read: ReadMemory, budget: QueryBudget) -> DefinitionResult: ...


class UnimplementedMemoryQueryPort:
    """Explicit unsupported methods; never return an unchanged state or empty facts."""
    def read(self, request, budget=QueryBudget()):
        raise UnsupportedSemantics('MemoryQueryPort.read requires the P5 heap engine')

    def write(self, request, budget=QueryBudget()):
        raise UnsupportedSemantics('MemoryQueryPort.write requires the P5 heap engine')

    def resolve_alias(self, state, left, right, budget=QueryBudget()):
        raise UnsupportedSemantics('Alias resolution requires P5; distinct IDs do not prove NoAlias')

    def points_to(self, state, address, budget=QueryBudget()):
        raise UnsupportedSemantics('Points-to computation requires P5')

    def resolve_definition(self, read, budget=QueryBudget()):
        raise UnsupportedSemantics('Memory definition resolution requires P5')
