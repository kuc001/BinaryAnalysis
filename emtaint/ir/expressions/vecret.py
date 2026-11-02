"""Adapt the VEX vector-return marker to the legacy IR visitor interface."""

from pyvex.expr import VECRET

from ..visitors import IRVisitor


class VECRET(VECRET):
    """Represent the special VEX vector-return marker expression."""

    def __init__(self) -> None:
        super().__init__()

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_vecret``."""

        return visitor.visit_vecret(self)
