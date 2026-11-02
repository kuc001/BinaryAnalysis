"""Classify a legacy SSA assignment produced by a register read."""

from pyvex.expr import IRExpr

from .wr_tmp import WrTmp
from ..visitors import IRVisitor


class WrGet(WrTmp):
    """Assign a guest-register read to one VEX SSA temporary."""

    def __init__(self, tmp: int, data: IRExpr) -> None:
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this assignment to the register-read visitor."""

        return visitor.visit_wr_get(self)
