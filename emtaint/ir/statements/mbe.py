from pyvex.stmt import MBE
from ..visitors import IRVisitor

class MBE(MBE):

    def __init__(self, event):
        super().__init__(event)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_mbe(self)
