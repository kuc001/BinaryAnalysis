from pyvex.expr import Load
from ..visitors import IRVisitor

class Load(Load):
    """
    A load from memory.
    """

    def __init__(self, end, ty, addr):
        super().__init__(end, ty, addr)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_load(self)
