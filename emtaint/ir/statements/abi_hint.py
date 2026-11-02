"""Adapt VEX ABI hints to the legacy IR visitor interface."""

from pyvex.stmt import AbiHint
from pyvex.expr import IRExpr

from ..visitors import IRVisitor


class AbiHint(AbiHint):
    """Retain platform ABI metadata emitted by VEX for one code range."""

    def __init__(self, base: IRExpr, length: int, nia: IRExpr) -> None:
        super().__init__(base, length, nia)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_abi_hint``."""

        return visitor.visit_abi_hint(self)
