from pyvex.expr import Qop
from ..visitors import IRVisitor

class Qop(Qop):
    """
    A quaternary operation (4 arguments).
    """

    def __init__(self, op, args):
        super().__init__(op, args)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_qop(self)

