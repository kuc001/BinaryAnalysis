"""Expose legacy visitor and operand metadata for VEX unary operations."""

from pyvex.expr import Unop, IRExpr

from ..visitors import IRVisitor


class Unop(Unop):
    """Represent a one-operand VEX operation without changing bit semantics."""

    def __init__(self, op: str, args: list[IRExpr]) -> None:
        super().__init__(op, args)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_unop``."""

        return visitor.visit_unop(self)

    def get_size(self) -> int:
        """Return the operation result width in bits as defined by VEX."""

        ty = self.result_type(None)
        size = self.result_size(ty)
        return size

    def get_args_info(self) -> list[int | str]:
        """Return the legacy identity of the unary operand."""

        info: list[int | str] = []
        for arg in self.args:
            try:
                info.append(arg.get_name())
            except AttributeError as error:
                raise ValueError(
                    f"Unary operand does not expose get_name(): {arg!r} in {self!r}"
                ) from error
        return info
