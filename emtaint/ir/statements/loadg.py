from pyvex.stmt import LoadG
from pyvex.expr import IRExpr
from ..visitors import IRVisitor

class LoadG(LoadG):
    """
    A guarded load.
    """

    def __init__(self, end: str, cvt: str, dst: int, addr: IRExpr, alt: IRExpr, guard: IRExpr):
        super().__init__(end, cvt, dst, addr, alt, guard)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_loadg(self)
    
    def get_def(self):
        return 't%d' % self.dst
    
    def get_use_with_guard(self):
        return self.addr
    
    def get_use_without_guard(self):
        return self.alt
    
    def get_guard(self):
        return self.guard