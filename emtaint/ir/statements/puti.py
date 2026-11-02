"""Adapt indexed guest-register writes to the legacy visitor interface."""

from pyvex.stmt import PutI
from pyvex.expr import IRExpr, IRRegArray

from ..visitors import IRVisitor


class PutI(PutI):
    """Write a register-array element selected by a VEX index expression."""

    def __init__(
        self, descr: IRRegArray, ix: IRExpr, data: IRExpr, bias: int
    ) -> None:
        super().__init__(descr, ix, data, bias)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_puti``."""

        return visitor.visit_puti(self)
