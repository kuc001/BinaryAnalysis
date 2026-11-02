"""Adapt VEX four-operand operations to the legacy IR visitor interface."""

from pyvex.expr import IRExpr, Qop

from ..visitors import IRVisitor


class Qop(Qop):
    """Represent a four-operand VEX operation without changing its semantics."""

    def __init__(self, op: str, args: list[IRExpr]) -> None:
        super().__init__(op, args)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_qop``."""

        return visitor.visit_qop(self)
