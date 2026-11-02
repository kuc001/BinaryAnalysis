"""Represent integer constants in the legacy PAG value domain."""

from pyvex.expr import IRExpr

from emtaint.assembly.code_location import CodeLocation

from .var_type import EMType
from .value import Value, ValueKind


class ConsValue(Value):
    """Carry an integer literal and optional symbolic compatibility payload."""

    def __init__(
        self,
        cons: int,
        size: int | None,
        kind: ValueKind,
        value: object | None = None,
        ty: EMType | None = None,
        loc: CodeLocation | None = None,
        expr: IRExpr | None = None,
    ) -> None:
        super().__init__(kind, size, value, ty, loc, expr)
        self.cons = cons

    def __str__(self) -> str:
        if self.value is not None:
            return f"<ConsValue[{self.loc}] {self.value}>"
        return f"<ConsValue[{self.loc}] 0x{self.cons:x}>"

    def __repr__(self) -> str:
        return self.__str__()

    def get_literal(self) -> str:
        """Return the integer in stable hexadecimal legacy form."""

        return f"0x{self.cons:x}"

    def with_same_value(self, other: Value) -> bool:
        """Compare constants by exact integer payload."""

        if not isinstance(other, ConsValue):
            return False
        return self.cons == other.cons
