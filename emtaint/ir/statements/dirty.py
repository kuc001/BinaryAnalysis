from pyvex.stmt import Dirty
from ..visitors import IRVisitor

class Dirty(Dirty):

    def __init__(self, cee, guard, args, tmp, mFx, mAddr, mSize, nFxState):
        super().__init__(cee, guard, args, tmp, mFx, mAddr, mSize, nFxState)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_dirty(self)
        
