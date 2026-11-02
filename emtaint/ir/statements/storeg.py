"""Adapt guarded VEX stores to legacy def-use and visitor interfaces."""

from pyvex.stmt import StoreG
from pyvex.expr import IRExpr

from ..visitors import IRVisitor


class StoreG(StoreG):
    """Write memory only when an explicit VEX guard evaluates true."""

    def __init__(
        self, end: str, addr: IRExpr, data: IRExpr, guard: IRExpr
    ) -> None:
        super().__init__(end, addr, data, guard)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_storeg``."""

        return visitor.visit_storeg(self)

    def get_def(self) -> IRExpr:
        """Return the address expression identifying the possible write."""

        return self.addr

    def get_use(self) -> IRExpr:
        """Return the value expression consumed when the guard is true."""

        return self.data

    def get_guard(self) -> IRExpr:
        """Return the condition controlling whether memory is written."""

        return self.guard
