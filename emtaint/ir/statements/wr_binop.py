"""Classify a legacy SSA assignment produced by a binary operation."""

from pyvex.expr import IRExpr

from .wr_tmp import WrTmp
from ..visitors import IRVisitor


class WrBinop(WrTmp):
    """Assign a binary-operation result to one VEX SSA temporary."""

    def __init__(self, tmp: int, data: IRExpr) -> None:
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this assignment to the binary-operation visitor."""

        return visitor.visit_wr_binop(self)
