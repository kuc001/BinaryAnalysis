"""Classify a legacy register-based store with temporary-derived data."""

from pyvex.expr import IRExpr

from .store import Store
from ..visitors import IRVisitor


class RegStoreTmp(Store):
    """Write temporary-derived data through a register-derived address."""

    def __init__(self, addr: IRExpr, data: IRExpr, end: str) -> None:
        super().__init__(addr, data, end)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to the register-temporary store visitor."""

        return visitor.visit_reg_store_tmp(self) 
