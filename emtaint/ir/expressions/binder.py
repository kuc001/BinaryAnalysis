
from pyvex.expr import Binder
from ..visitors import IRVisitor

class Binder(Binder):
    """
    Used only in pattern matching within Vex. Should not be seen outside of Vex.
    """

    def __init__(self, binder):
        super.__init__(binder)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_binder(self)
    