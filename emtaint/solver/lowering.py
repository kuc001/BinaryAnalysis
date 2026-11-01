"""P3 lowering boundary. Producing SMT memory semantics is P5, not a DTO cast."""
from dataclasses import dataclass
from enum import Enum
from typing import Protocol

from emtaint.core.contracts import (Record, Assessment, SymbolicExprId, TypeKind, same_scope)
from emtaint.core.identity import integer
from emtaint.core import Completeness
from emtaint.memory.state import MemorySnapshot
from emtaint.memory.query_port import QueryBudget
from .port import SolverQuery


class LoweringStatus(str, Enum):
    READY = 'ready'
    UNSUPPORTED = 'unsupported'
    UNKNOWN = 'unknown'
    INCOMPLETE = 'incomplete'
    TIMEOUT = 'timeout'
    ERROR = 'error'


@dataclass(frozen=True)
class LoweringRequest(Record):
    snapshot: MemorySnapshot
    expression: SymbolicExprId
    guards: tuple[SymbolicExprId, ...] = ()
    budget: QueryBudget = QueryBudget()
    operation: str = 'eval'
    limit: int = 1

    def __post_init__(self):
        super().__post_init__()
        same_scope(self.snapshot.scope, self.expression, *self.guards)
        nodes = {node.id: node for node in self.snapshot.expressions}
        if self.expression not in nodes or any(guard not in nodes or nodes[guard].type.kind.value != 'bool' for guard in self.guards):
            raise ValueError('Lowering needs declared expressions and boolean guards')
        if self.operation not in ('check', 'eval', 'min', 'max'):
            raise ValueError('Unknown lowering query operation')
        integer(self.limit, 'evaluation limit', 1)
        if self.limit > 64 or ((self.operation == 'check') != (nodes[self.expression].type.kind == TypeKind.BOOL)):
            raise ValueError('Lowering query sort/limit mismatch')


@dataclass(frozen=True)
class LoweringResult(Record):
    status: LoweringStatus
    query: SolverQuery | None
    formula_origins: tuple[str, ...]
    assessment: Assessment

    def __post_init__(self):
        super().__post_init__()
        if (self.status == LoweringStatus.READY) != (self.query is not None):
            raise ValueError('Only READY lowering may contain a SolverQuery')
        if self.status != LoweringStatus.READY and self.assessment.status == Completeness.COMPLETE:
            raise ValueError('Failed/unknown lowering cannot be marked complete')
        if not self.formula_origins:
            raise ValueError('Lowering results require formula provenance')
        if self.query is not None:
            self.query.validate()

    def __bool__(self):
        raise TypeError('Lowering status is explicit; unsupported is not UNSAT')


class SolverLowering(Protocol):
    def lower(self, request: LoweringRequest) -> LoweringResult: ...


class UnimplementedSolverLowering:
    def lower(self, request):
        if not isinstance(request, LoweringRequest):
            raise TypeError('Only typed lowering requests are accepted; raw legacy markers are forbidden')
        return LoweringResult(LoweringStatus.UNSUPPORTED, None,
            tuple(origin.id for origin in request.snapshot.origin_map),
            Assessment(unsupported_ops=('SolverLowering',), diagnostics=(
                'P5 semantic lowering is unimplemented; no solver was invoked',)))
