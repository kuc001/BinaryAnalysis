from pyvex.stmt import AbiHint
from ..visitors import IRVisitor

class AbiHint(AbiHint):
    """
    An ABI hint, provides specific information about this platform's ABI.
    """

    def __init__(self, base, length, nia):
        super().__init__(base, length, nia)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_abi_hint(self)
