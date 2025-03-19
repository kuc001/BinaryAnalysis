from pyvex.expr import Const
from pyvex.const import IRConst
from ..visitors import IRVisitor

class Const(Const):
    """
    A constant expression.
    """

    def __init__(self, con: IRConst):
        super().__init__(con)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_const(self)

    def get_name(self):
        return self.con.value
