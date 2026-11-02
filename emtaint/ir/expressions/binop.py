"""Expose legacy visitor and operand metadata for VEX binary operations."""

from pyvex.expr import Binop, IRExpr

from ..visitors import IRVisitor


class Binop(Binop):
    """Represent a two-operand VEX operation without changing its bit semantics."""

    def __init__(
        self, op: str, args: list[IRExpr], op_int: int | None = None
    ) -> None:
        super().__init__(op, args, op_int)

    def accept(self, visitor: IRVisitor) -> object:
        """Dispatch this expression to ``visitor.visit_binop``."""

        return visitor.visit_binop(self)

    def get_size(self) -> int:
        """Return the operation result width in bits as defined by VEX."""

        return self.result_size(self.op)

    def get_args_info(self) -> list[tuple[int | str, int]]:
        """Return each legacy operand identity and its effective bit width."""

        info: list[tuple[int | str, int]] = []
        for arg in self.args:
            try:
                info.append((arg.get_name(), arg.get_size()))
            except AttributeError:
                info.append((arg.get_name(), self.get_size()))
        return info
