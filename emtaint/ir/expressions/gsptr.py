from pyvex.expr import GSPTR
from ..visitors import IRVisitor

class GSPTR(GSPTR):

    def __init__(self):
        super().__init__()

    def accept(self, visitor: IRVisitor):
        return visitor.visit_gsptr(self)

