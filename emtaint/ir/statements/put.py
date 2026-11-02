"""Adapt fixed guest-register writes to legacy def-use and visitor APIs."""

from pyvex.stmt import Put
from pyvex.expr import IRExpr

from ..visitors import IRVisitor


class Put(Put):
    """Write an expression to a named guest register at a fixed offset."""

    def __init__(self, data: IRExpr, offset: int, name: str) -> None:
        super().__init__(data, offset)
        self.name = name

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_put``."""

        return visitor.visit_put(self)

    def get_name(self) -> str:
        """Return the architecture register name supplied by the adapter."""

        return self.name

    def get_def(self) -> str:
        """Return the register name defined by this write."""

        return self.name

    def get_use(self) -> IRExpr:
        """Return the value expression consumed by this register write."""

        return self.data
