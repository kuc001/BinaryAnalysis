"""Classify an SSA assignment loaded from a constant-derived address."""

from pyvex.expr import IRExpr

from .wr_tmp import WrTmp
from ..visitors import IRVisitor


class WrLoadCons(WrTmp):
    """Assign a constant-address memory load to one VEX SSA temporary."""

    def __init__(self, tmp: int, data: IRExpr) -> None:
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this assignment to the constant-address load visitor."""

        return visitor.visit_wr_load_cons(self)
