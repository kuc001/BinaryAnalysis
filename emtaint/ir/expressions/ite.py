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
    
    def get_cond(self):
        return self.cond
    
    def get_iffalse(self):
        return self.iffalse
    
    def get_iftrue(self):
        return self.iftrue