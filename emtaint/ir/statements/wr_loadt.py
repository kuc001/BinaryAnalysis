from pyvex.expr import IRExpr
from .wr_tmp import WrTmp
from ..visitors import IRVisitor

class WrLoadTmp(WrTmp):
    """
    Assign a load value to a temporary.  Note that SSA rules require each tmp is only assigned to once.  IR sanity checking
    will reject any block containing a temporary which is not assigned to exactly once.
    """

    def __init__(self, tmp, data: IRExpr):
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_wr_load_tmp(self)
