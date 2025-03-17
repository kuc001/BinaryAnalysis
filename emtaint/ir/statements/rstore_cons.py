from pyvex.expr import IRExpr
from .store import Store
from ..visitors import IRVisitor

class RegStoreCons(Store):
    """
    Write a value to memory..
    """

    def __init__(self, addr: IRExpr, data: IRExpr, end: str):
        super().__init__(addr, data, end)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_reg_store_cons(self)
    