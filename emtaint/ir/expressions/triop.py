from pyvex.expr import Triop
from ..visitors import IRVisitor

class Triop(Triop):
    """
    A ternary operation (3 arguments)
    """

    def __init__(self, op, args):
        super().__init__(op, args)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_triop(self)
