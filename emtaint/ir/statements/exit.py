"""Adapt conditional VEX block exits to the legacy visitor interface."""

from pyvex.stmt import Exit
from pyvex.expr import IRExpr
from pyvex.const import IRConst

from ..visitors import IRVisitor


class Exit(Exit):
    """Conditionally leave an IRSB for an explicit constant destination."""

    def __init__(
        self, guard: IRExpr, dst: IRConst, jk: str, offsIP: int
    ) -> None:
        super().__init__(guard, dst, jk, offsIP)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_exit``."""

        return visitor.visit_exit(self)
