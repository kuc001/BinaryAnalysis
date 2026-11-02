"""Adapt VEX three-operand operations to the legacy IR visitor interface."""

from pyvex.expr import IRExpr, Triop

from ..visitors import IRVisitor


class Triop(Triop):
    """Represent a three-operand VEX operation without changing its semantics."""

    def __init__(self, op: str, args: list[IRExpr]) -> None:
        super().__init__(op, args)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_triop``."""

        return visitor.visit_triop(self)
