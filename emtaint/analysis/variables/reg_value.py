"""Represent named architecture registers in the legacy PAG value domain."""

from pyvex.expr import IRExpr

from emtaint.assembly.code_location import CodeLocation

from .var_type import EMType
from .value import Value, ValueKind


class RegValue(Value):
    """Carry a stable architecture register name and its source metadata."""

    def __init__(
        self,
        name: str,
        size: int | None,
        kind: ValueKind,
        value: object | None = None,
        ty: EMType | None = None,
        loc: CodeLocation | None = None,
        expr: IRExpr | None = None,
    ) -> None:
        super().__init__(kind, size, value, ty, loc, expr)

        self.name = name
        self.add_ref(name)

    def __str__(self) -> str:
        if self.value is not None:
            return f"<RegValue[{self.loc}] {self.value}>"
        return f"<RegValue[{self.loc}] {self.name}>"

    def __repr__(self) -> str:
        return self.__str__()

    def get_literal(self) -> str:
        """Return the exact architecture register name."""

        return self.name

    def with_same_value(self, other: Value) -> bool:
        """Compare register values by architecture register identity."""

        if not isinstance(other, RegValue):
            return False
        return self.name == other.name
