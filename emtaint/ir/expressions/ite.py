"""Adapt VEX conditional expressions to the legacy IR visitor interface."""

from pyvex.expr import ITE, IRExpr

from ..visitors import IRVisitor


class ITE(ITE):
    """Select one of two equally typed VEX expressions by a condition."""

    def __init__(self, cond: IRExpr, iffalse: IRExpr, iftrue: IRExpr) -> None:
        super().__init__(cond, iffalse, iftrue)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_ite``."""

        return visitor.visit_ite(self)

    def get_cond(self) -> IRExpr:
        """Return the condition without evaluating either value branch."""

        return self.cond

    def get_iffalse(self) -> IRExpr:
        """Return the value selected when the condition is false."""

        return self.iffalse

    def get_iftrue(self) -> IRExpr:
        """Return the value selected when the condition is true."""

        return self.iftrue
