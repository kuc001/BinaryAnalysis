"""Adapt VEX load-linked/store-conditional statements to legacy visitors."""

from pyvex.stmt import LLSC
from pyvex.expr import IRExpr

from ..visitors import IRVisitor


class LLSC(LLSC):
    """Represent a load-linked or store-conditional memory operation.

    A ``None`` store value denotes load-linked; an expression denotes
    store-conditional. The distinction is preserved for downstream semantics.
    """

    def __init__(
        self, addr: IRExpr, storedata: IRExpr | None, result: int, end: str
    ) -> None:
        super().__init__(addr, storedata, result, end)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_llsc``."""

        return visitor.visit_llsc(self)
