"""Adapt VEX constants to the legacy IR visitor and naming interface."""

from pyvex.expr import Const
from pyvex.const import IRConst

from ..visitors import IRVisitor


class Const(Const):
    """Represent an immutable VEX constant expression."""

    def __init__(self, con: IRConst) -> None:
        super().__init__(con)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_const``."""

        return visitor.visit_const(self)

    def get_name(self) -> int:
        """Return the constant's exact unsigned VEX payload."""

        return self.con.value
