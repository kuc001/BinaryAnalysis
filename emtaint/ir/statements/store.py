"""Adapt VEX memory stores to legacy def-use and visitor interfaces."""

from pyvex.stmt import Store
from pyvex.expr import IRExpr

from ..visitors import IRVisitor


class Store(Store):
    """Write a value to memory with explicit VEX endianness."""

    def __init__(self, addr: IRExpr, data: IRExpr, end: str) -> None:
        super().__init__(addr, data, end)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_store``."""

        return visitor.visit_store(self)

    def get_use(self) -> IRExpr:
        """Return the value expression consumed by the memory write."""

        return self.data

    def get_def(self) -> IRExpr:
        """Return the address expression identifying the written memory."""

        return self.addr
