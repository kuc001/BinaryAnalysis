"""Classify a legacy global store whose address is temporary-derived."""

from pyvex.expr import IRExpr

from .store import Store
from ..visitors import IRVisitor


class GlobalStoreTmp(Store):
    """Write through a global address classified as temporary-derived."""

    def __init__(self, addr: IRExpr, data: IRExpr, end: str) -> None:
        super().__init__(addr, data, end)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to the global-temporary store visitor."""

        return visitor.visit_global_store_tmp(self)
