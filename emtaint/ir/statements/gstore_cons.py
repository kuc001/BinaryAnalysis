"""Classify a legacy global store whose address is constant-derived."""

from pyvex.expr import IRExpr

from .store import Store
from ..visitors import IRVisitor


class GlobalStoreCons(Store):
    """Write through a global address classified as constant-derived."""

    def __init__(self, addr: IRExpr, data: IRExpr, end: str) -> None:
        super().__init__(addr, data, end)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to the global-constant store visitor."""

        return visitor.visit_global_store_cons(self)
