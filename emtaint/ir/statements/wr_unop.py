"""Classify a legacy SSA assignment produced by a unary operation."""

from pyvex.expr import IRExpr

from .wr_tmp import WrTmp
from ..visitors import IRVisitor


class WrUnop(WrTmp):
    """Assign a unary-operation result to one VEX SSA temporary."""

    def __init__(self, tmp: int, data: IRExpr) -> None:
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this assignment to the unary-operation visitor."""

        return visitor.visit_wr_unop(self)
