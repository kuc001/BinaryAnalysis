"""Represent named VEX temporaries in the legacy PAG value domain."""

from pyvex.expr import IRExpr

from emtaint.assembly.code_location import CodeLocation

from .var_type import EMType
from .value import Value, ValueKind


class TmpValue(Value):
    """Carry a stable SSA temporary name and its source metadata."""

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
            return f"<TmpValue[{self.loc}] {self.value}>"
        return f"<TmpValue[{self.loc}] {self.name}>"

    def __repr__(self) -> str:
        return self.__str__()

    def get_literal(self) -> str:
        """Return the stable VEX temporary name."""

        return self.name

    def with_same_value(self, other: Value) -> bool:
        """Compare temporary values by SSA temporary identity."""

        if not isinstance(other, TmpValue):
            return False
        return self.name == other.name
