"""Adapt pure VEX helper calls to the legacy IR visitor interface."""

from pyvex.expr import CCall, IRCallee, IRExpr

from ..visitors import IRVisitor


class CCall(CCall):
    """Represent a pure VEX helper call and its explicit return type."""

    def __init__(self, retty: str, cee: IRCallee, args: list[IRExpr]) -> None:
        super().__init__(retty, cee, args)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_ccall``."""

        return visitor.visit_ccall(self)
