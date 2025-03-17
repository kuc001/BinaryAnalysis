from pyvex.expr import CCall
from ..visitors import IRVisitor

class CCall(CCall):
    """
    A call to a pure (no side-effects) helper C function.
    """
    def __init__(self, retty, cee, args):
        super().__init__(retty, cee, args)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_ccall(self)
