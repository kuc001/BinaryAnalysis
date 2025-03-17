from pyvex.expr import VECRET
from ..visitors import IRVisitor

class VECRET(VECRET):
    
    def __init__(self):
        super().__init__()

    def accept(self, visitor: IRVisitor):
        return visitor.visit_vecret(self)
