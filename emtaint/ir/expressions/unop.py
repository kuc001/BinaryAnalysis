from pyvex.expr import Unop, IRExpr
from ..visitors import IRVisitor

class Unop(Unop):
    """
    A unary operation (1 argument).
    """

    def __init__(self, op: str, args: list[IRExpr]):
        super().__init__(op, args)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_unop(self)
