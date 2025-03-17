from pyvex.stmt import PutI
from ..visitors import IRVisitor

class PutI(PutI):
    """
    Write to a guest register, at a non-fixed offset in the guest state.
    """

    def __init__(self, descr, ix, data, bias):
        super().__init__(descr, ix, data, bias)
        
    def accept(self, visitor: IRVisitor):
        return visitor.visit_puti(self)
