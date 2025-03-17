from pyvex.stmt import LLSC
from pyvex.expr import IRExpr
from ..visitors import IRVisitor

class LLSC(LLSC):
    """
    Either Load-Linked or Store-Conditional, depending on STOREDATA. If STOREDATA is NULL then this is a Load-Linked,
    else it is a Store-Conditional.
    """

    def __init__(self, addr: IRExpr, storedata: IRExpr, result: int, end: str):
        super().__init__(addr, storedata, result, end)
        

    def accept(self, visitor: IRVisitor):
        return visitor.visit_llsc(self)
