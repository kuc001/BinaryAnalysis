"""Adapt side-effecting VEX helper calls to the legacy visitor interface."""

from pyvex.stmt import Dirty
from pyvex.expr import IRCallee, IRExpr

from ..visitors import IRVisitor


class Dirty(Dirty):
    """Represent a guarded helper call with explicit memory-effect metadata."""

    def __init__(
        self,
        cee: IRCallee,
        guard: IRExpr,
        args: list[IRExpr],
        tmp: int | None,
        mFx: str,
        mAddr: IRExpr | None,
        mSize: int,
        nFxState: int,
    ) -> None:
        super().__init__(cee, guard, args, tmp, mFx, mAddr, mSize, nFxState)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this helper statement to ``visitor.visit_dirty``."""

        return visitor.visit_dirty(self)
