from pyvex.stmt import Put
from pyvex.expr import IRExpr
from ..visitors import IRVisitor

class Put(Put):
    """
    Write to a guest register, at a fixed offset in the guest state.
    """

    def __init__(self, data: IRExpr, offset: int, name: str):
        super().__init__(data, offset)
        self.name = name

    def accept(self, visitor: IRVisitor):
        return visitor.visit_put(self)
    
    def get_name(self):
        return self.name

    def get_def(self):
        return self.name
    
    def get_use(self):
        return self.data