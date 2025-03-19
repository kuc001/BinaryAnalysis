from pyvex.expr import IRExpr
from .put import Put
from ..visitors import IRVisitor

class PutTmp(Put):
    """
    Write to a guest register, at a fixed offset in the guest state.
    """

    def __init__(self, data: IRExpr, offset: int, name: str):
        super().__init__(data, offset, name)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_put_tmp(self)
    