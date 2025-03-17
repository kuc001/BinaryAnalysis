from pyvex.stmt import Exit
from pyvex.expr import IRExpr
from pyvex.const import IRConst
from ..visitors import IRVisitor

class Exit(Exit):
    """
    A conditional exit from the middle of an IRSB.
    """

    def __init__(self, guard: IRExpr, dst: IRConst, jk: str, offsIP: int):
        super().__init__(guard, dst, jk, offsIP)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_exit(self)