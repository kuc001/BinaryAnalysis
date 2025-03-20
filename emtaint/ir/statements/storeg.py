from pyvex.stmt import StoreG
from ..visitors import IRVisitor

class StoreG(StoreG):
    """
    A guarded store.
    """

    def __init__(self, end, addr, data, guard):
        super().__init__(end, addr, data, guard)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_storeg(self)
    
    def get_def(self):
        return self.addr
    
    def get_use(self):
        return self.data
    
    def get_guard(self):
        return self.guard
    