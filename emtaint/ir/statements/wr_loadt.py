"""Classify an SSA assignment loaded from a temporary-derived address."""

from pyvex.expr import IRExpr

from .wr_tmp import WrTmp
from ..visitors import IRVisitor


class WrLoadTmp(WrTmp):
    """Assign a temporary-address memory load to one VEX SSA temporary."""

    def __init__(self, tmp: int, data: IRExpr) -> None:
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this assignment to the temporary-address load visitor."""

        return visitor.visit_wr_load_tmp(self)
