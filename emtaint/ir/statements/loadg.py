"""Adapt guarded VEX loads to legacy def-use and visitor interfaces."""

from pyvex.stmt import LoadG
from pyvex.expr import IRExpr

from ..visitors import IRVisitor


class LoadG(LoadG):
    """Load memory conditionally and retain the alternate value explicitly."""

    def __init__(
        self,
        end: str,
        cvt: str,
        dst: int,
        addr: IRExpr,
        alt: IRExpr,
        guard: IRExpr,
    ) -> None:
        super().__init__(end, cvt, dst, addr, alt, guard)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this statement to ``visitor.visit_loadg``."""

        return visitor.visit_loadg(self)

    def get_def(self) -> str:
        """Return the SSA temporary defined by the guarded load."""

        return f't{self.dst}'

    def get_use_with_guard(self) -> IRExpr:
        """Return the memory address used when the guard is true."""

        return self.addr

    def get_use_without_guard(self) -> IRExpr:
        """Return the alternate value used when the guard is false."""

        return self.alt

    def get_guard(self) -> IRExpr:
        """Return the expression controlling whether memory is read."""

        return self.guard
