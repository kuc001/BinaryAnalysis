"""Classify a legacy SSA assignment produced by a conditional expression."""

from pyvex.expr import IRExpr

from .wr_tmp import WrTmp
from ..visitors import IRVisitor


class WrITE(WrTmp):
    """Assign a conditional-expression result to one VEX SSA temporary."""

    def __init__(self, tmp: int, data: IRExpr) -> None:
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this assignment to the conditional-expression visitor."""

        return visitor.visit_wr_ite(self)
