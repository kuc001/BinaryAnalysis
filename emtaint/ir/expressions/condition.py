from pyvex.expr import ITE
from ..visitors import IRVisitor

class ITE(ITE):
    """
    An if-then-else expression.
    """

    def __init__(self, cond, iffalse, iftrue):
        super().__init__(cond, iffalse, iftrue)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_ite(self)
