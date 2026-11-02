"""Adapt the VEX guest-state-pointer marker to the legacy visitor API."""

from pyvex.expr import GSPTR

from ..visitors import IRVisitor


class GSPTR(GSPTR):
    """Represent the VEX guest-state pointer marker expression."""

    def __init__(self) -> None:
        super().__init__()

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_gsptr``."""

        return visitor.visit_gsptr(self)
