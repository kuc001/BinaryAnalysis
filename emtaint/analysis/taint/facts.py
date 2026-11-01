"""Private P7 scalar taint identities; symbolic values remain in the SSE DAG."""
from dataclasses import dataclass

from emtaint.core import ContextId, ProgramPoint
from emtaint.core.contracts import SymbolicExprId


@dataclass(frozen=True)
class ScalarTaintFact:
    """A source-return fact tied to a CIR value and its execution context."""

    value_id: str
    point: ProgramPoint
    context: ContextId
    guard: SymbolicExprId | None
    source_site: int
    origin: str
    uncertain: bool

    def __post_init__(self) -> None:
        if not self.value_id or not self.origin or self.source_site < 0:
            raise ValueError('Scalar taint fact needs a value, origin and source site')
        if self.guard is not None and (
            self.guard.scope.function != self.point.block.function
            or self.guard.scope.context != self.context
        ):
            raise ValueError('Scalar taint guard has a different function/context')
