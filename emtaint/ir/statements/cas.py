"""Adapt atomic VEX compare-and-swap statements to legacy visitors."""

from pyvex.stmt import CAS
from pyvex.expr import IRExpr

from ..visitors import IRVisitor


class CAS(CAS):
    """Represent a single- or double-width atomic compare-and-swap."""

    def __init__(
        self,
        addr: IRExpr,
        dataLo: IRExpr,
        dataHi: IRExpr | None,
        expdLo: IRExpr,
        expdHi: IRExpr | None,
        oldLo: int,
        oldHi: int | None,
        end: str,
    ) -> None:
        super().__init__(addr, dataLo, dataHi, expdLo, expdHi, oldLo, oldHi, end)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this atomic statement to ``visitor.visit_cas``."""

        return visitor.visit_cas(self)
