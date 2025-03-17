from pyvex.expr import Get
from ..visitors import IRVisitor

class Get(Get):
    """
    Read a guest register, at a fixed offset in the guest state.
    """

    def __init__(self, offset: int, name: str, ty: str, ty_int: int | None = None):
        super().__init__(offset, ty, ty_int)
        self.name = name

    def accept(self, visitor: IRVisitor):
        return visitor.visit_get(self)

    def get_size(self):
        return self.result_size(self.ty)

    def get_name(self):
        return self.name