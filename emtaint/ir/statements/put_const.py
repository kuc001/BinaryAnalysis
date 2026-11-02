"""Classify a guest-register write with constant-derived input data."""

from pyvex.expr import IRExpr

from .put import Put
from ..visitors import IRVisitor


class PutConst(Put):
    """Write constant-derived data to a fixed guest register."""

    def __init__(self, data: IRExpr, offset: int, name: str) -> None:
        super().__init__(data, offset, name)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to the constant-register-write visitor."""

        return visitor.visit_put_const(self)
