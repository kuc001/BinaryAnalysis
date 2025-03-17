from pyvex.expr import RdTmp
from ..visitors import IRVisitor

class RdTmp(RdTmp):
    """
    Read the value held by a temporary.
    """

    def __init__(self, tmp):
        super().__init__(tmp)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_rdtmp(self)

    def get_name(self):
        return 't%d' % self.tmp