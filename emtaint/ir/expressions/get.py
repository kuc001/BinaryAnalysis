"""Adapt fixed guest-register reads to the legacy IR visitor interface."""

from pyvex.expr import Get

from ..visitors import IRVisitor


class Get(Get):
    """Read a named guest register at a fixed VEX guest-state offset."""

    def __init__(
        self, offset: int, name: str, ty: str, ty_int: int | None = None
    ) -> None:
        super().__init__(offset, ty, ty_int)
        self.name = name

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_get``."""

        return visitor.visit_get(self)

    def get_size(self) -> int:
        """Return the register-read width in bits according to VEX type data."""

        return self.result_size(self.ty)

    def get_name(self) -> str:
        """Return the architecture register name supplied by the adapter."""

        return self.name
