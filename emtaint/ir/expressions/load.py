"""Adapt a VEX memory-load expression to the legacy IR visitor interface."""

from pyvex.expr import IRExpr, Load

from ..visitors import IRVisitor


class Load(Load):
    """Represent a VEX load while preserving its address, type, and endianness."""

    def __init__(self, end: str, ty: str, addr: IRExpr) -> None:
        super().__init__(end, ty, addr)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_load``."""

        return visitor.visit_load(self)

    def get_size(self) -> int:
        """Return the loaded value width in bits according to its VEX type."""

        return self.result_size(self.ty)
