"""Define the common metadata contract for legacy PAG values."""

from __future__ import annotations

from enum import IntEnum

from pyvex.expr import IRExpr

from emtaint.assembly.code_location import CodeLocation

from .var_type import EMType


class ValueKind(IntEnum):
    """Classify the storage and semantic role of a legacy PAG value."""

    Const = 0  # 常量
    Global = 1  # 全局变量
    Array = 2  # 数组
    Struct = 3  # 结构体
    Pointer = 4  # 指针
    StackPtr = 5  # 栈指针
    GlobalPtr = 6  # 全局指针
    CodePtr = 7  # 执行代码的
    FunctionPtr = 8  # 函数指针
    StackAccess = 9  # 栈访问
    MemAccess = 10  # 内存访问
    ArrayAccess = 11  # 数组访问
    StructAccess = 12  # 结构体访问
    Condition = 13  # 条件
    Unknown = 14  # 未知

class Value:
    """Carry one legacy data-flow value and its source metadata.

    ``value`` is an opaque optional runtime payload at this compatibility
    boundary; symbolic reasoning must not assume a particular Claripy class.
    """

    def __init__(
        self,
        kind: ValueKind,
        size: int | None,
        value: object | None = None,
        ty: EMType | None = None,
        loc: CodeLocation | None = None,
        expr: IRExpr | None = None,
    ) -> None:
        self.kind = kind
        self.size = size
        self.value = value
        self.type = ty
        self.loc = loc
        self._expr = expr

        self.refs: set[str] = set()

    def __str__(self) -> str:
        return f"{self.kind} {self.value}"

    def __repr__(self) -> str:
        return self.__str__()

    def add_ref(self, ref: str) -> None:
        """Record a named register or temporary referenced by this value."""

        self.refs.add(ref)

    def get_literal(self) -> int | str | None:
        """Return a stable literal identity when the subclass has one."""

        return None

    def get_value(self) -> object | None:
        """Return the optional opaque runtime value payload."""

        return self.value

    def get_type(self) -> EMType | None:
        """Return the optional legacy type descriptor."""

        return self.type

    def with_same_value(self, other: Value) -> bool:
        """Test legacy value equality without conflating absent payloads."""

        if self.value is not None and other.value is not None:
            return self.value == other.value and self.kind == other.kind
        return False
