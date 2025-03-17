from pyvex.stmt import Store
from pyvex.expr import IRExpr
from ..visitors import IRVisitor

class Store(Store):
    """
    Write a value to memory..
    """

    def __init__(self, addr: IRExpr, data: IRExpr, end: str):
        super().__init__(addr, data, end)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_store(self)
    
    def get_use(self):
        return self.data