"""Represent binary-operation results in the legacy PAG value domain."""

from pyvex.expr import IRExpr

from emtaint.assembly.code_location import CodeLocation

from .var_type import EMType
from .value import Value, ValueKind


class BinopValue(Value):
    """Carry a VEX binary opcode and its validated legacy value operands."""

    def __init__(
        self,
        op: str,
        args: list[Value],
        size: int | None,
        kind: ValueKind,
        value: object | None = None,
        ty: EMType | None = None,
        loc: CodeLocation | None = None,
        expr: IRExpr | None = None,
    ) -> None:
        super().__init__(kind, size, value, ty, loc, expr)
        self.op = op
        self.args = args

        self._initialize_refs()

    def _initialize_refs(self) -> None:
        for arg in self.args:
            if isinstance(arg, Value):
                name = arg.get_literal()
                if isinstance(name, str):
                    self.add_ref(name)
            else:
                raise TypeError(
                    f"BinopValue arguments must be Value instances: {arg!r}"
                )
    
    def __str__(self) -> str:
        if self.value is not None:
            return f"<BinopValue[{self.loc}] {self.value}>"
        return "<BinopValue[{}] {}({})".format(
            self.loc,
            self.op[4:],
            ",".join(str(arg.get_literal()) for arg in self.args),
        )

    def __repr__(self) -> str:
        return self.__str__()

    def get_literal(self) -> str:
        """Return a stable comma-separated identity for the operands."""

        return ",".join(str(arg.get_literal()) for arg in self.args)
