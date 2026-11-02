"""Classify a legacy register-based store with constant-derived data."""

from pyvex.expr import IRExpr

from .store import Store
from ..visitors import IRVisitor


class RegStoreCons(Store):
    """Write constant-derived data through a register-derived address."""

    def __init__(self, addr: IRExpr, data: IRExpr, end: str) -> None:
        super().__init__(addr, data, end)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to the register-constant store visitor."""

        return visitor.visit_reg_store_cons(self)
