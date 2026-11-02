"""Adapt a VEX temporary read to the legacy IR visitor and naming API."""

from pyvex.expr import RdTmp

from ..visitors import IRVisitor


class RdTmp(RdTmp):
    """Read a VEX SSA temporary by its integer identifier."""

    def __init__(self, tmp: int) -> None:
        super().__init__(tmp)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_rdtmp``."""

        return visitor.visit_rdtmp(self)

    def get_name(self) -> str:
        """Return the stable legacy name for this VEX temporary."""

        return f't{self.tmp}'
