"""Adapt indexed guest-register reads to the legacy IR visitor interface."""

from pyvex.expr import GetI, IRExpr, IRRegArray

from ..visitors import IRVisitor


class GetI(GetI):
    """Read a register-array element selected by a VEX index expression."""

    def __init__(self, descr: IRRegArray, ix: IRExpr, bias: int) -> None:
        super().__init__(descr, ix, bias)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_geti``."""

        return visitor.visit_geti(self)
