from pyvex.expr import GetI
from ..visitors import IRVisitor

class GetI(GetI):
    """
    Read a guest register at a non-fixed offset in the guest state.
    """

    def __init__(self, descr, ix, bias):
        super().__init__(descr, ix, bias)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_geti(self)
