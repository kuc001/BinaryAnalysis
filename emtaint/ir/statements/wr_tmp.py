from pyvex.stmt import WrTmp
from pyvex.expr import IRExpr
from ..visitors import IRVisitor

class WrTmp(WrTmp):
    """
    Assign a value to a temporary.  Note that SSA rules require each tmp is only assigned to once.  IR sanity checking
    will reject any block containing a temporary which is not assigned to exactly once.
    """

    def __init__(self, tmp, data: IRExpr):
        super().__init__(tmp, data)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_wr_tmp(self)
    
    def get_def(self):
        return 't%d' % self.tmp
    
    def get_use(self):
        return self.data
