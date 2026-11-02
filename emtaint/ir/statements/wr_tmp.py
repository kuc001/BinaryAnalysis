"""Adapt VEX temporary assignments to legacy SSA def-use interfaces."""

from pyvex.stmt import WrTmp
from pyvex.expr import IRExpr

from ..visitors import IRVisitor


class WrTmp(WrTmp):
    """Assign one expression to a VEX SSA temporary exactly once."""

    def __init__(self, tmp: int, data: IRExpr) -> None:
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_wrtmp``."""

        return visitor.visit_wr_tmp(self)

    def get_def(self) -> str:
        """Return the stable legacy name defined by this SSA assignment."""

        return f't{self.tmp}'

    def get_use(self) -> IRExpr:
        """Return the expression consumed by this SSA assignment."""

        return self.data
