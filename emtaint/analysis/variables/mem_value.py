"""Represent legacy PAG memory reads and writes by their address value."""

from pyvex.expr import IRExpr

from emtaint.assembly.code_location import CodeLocation

from .var_type import EMType
from .value import Value, ValueKind


class MemValue(Value):
    """Carry a memory action and the value that computes its address."""

    def __init__(
        self,
        addr: Value,
        size: int | None,
        kind: ValueKind,
        action: str,
        value: object | None = None,
        ty: EMType | None = None,
        loc: CodeLocation | None = None,
        expr: IRExpr | None = None,
    ) -> None:
        super().__init__(kind, size, value, ty, loc, expr)
        self.addr = addr
        self.action = action

    def __str__(self) -> str:
        if self.value is not None:
            return f"<MemValue[{self.loc}] {self.value}>"
        if isinstance(self.addr, Value):
            return f"<MemValue[{self.loc}] {self.action}({self.addr.get_literal()})>"
        raise ValueError(f"The address of the mem value {self} is not a VarNode.")

    def __repr__(self) -> str:
        return self.__str__()
