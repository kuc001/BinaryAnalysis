from pyvex.stmt import CAS
from ..visitors import IRVisitor

class CAS(CAS):
    """
    an atomic compare-and-swap operation.
    """

    def __init__(self, addr, dataLo, dataHi, expdLo, expdHi, oldLo, oldHi, end):
        super().__init__(addr, dataLo, dataHi, expdLo, expdHi, oldLo, oldHi, end)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_cas(self)
