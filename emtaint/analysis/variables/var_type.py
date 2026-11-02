"""Define legacy PAG type categories and the compatibility inference hook."""

from enum import IntEnum

from pyvex.expr import IRExpr


class TypeKind(IntEnum):
    """Classify legacy scalar, pointer, aggregate, and function types."""

    EMType = 0
    PointerTy = 1
    IntegerTy = 2
    FunctionTy = 3
    StructTy = 4
    ArrayTy = 5
    OtherTy = 6

class EMType:
    """Describe a legacy value type and whether it denotes one scalar value."""

    def __init__(
        self, kind: TypeKind | None = None, is_single_val_ty: bool = True
    ) -> None:
        self._kind = kind
        self._is_single_val_ty = is_single_val_ty

    @property
    def kind(self) -> TypeKind | None:
        """Return the declared legacy type category, if one is known."""

        return self._kind

    def is_single_val_ty(self) -> bool:
        """Report whether the type denotes a single non-aggregate value."""

        return self._is_single_val_ty


class PointerType(EMType):
    """Describe a legacy pointer value."""

    def __init__(self, is_single_val_ty: bool = True) -> None:
        super().__init__(TypeKind.PointerTy, is_single_val_ty)


class IntegerType(EMType):
    """Describe a legacy integer value."""

    def __init__(self, is_single_val_ty: bool = True) -> None:
        super().__init__(TypeKind.IntegerTy, is_single_val_ty)


class FunctionType(EMType):
    """Describe a legacy function type."""

    def __init__(self, is_single_val_ty: bool = True) -> None:
        super().__init__(TypeKind.FunctionTy, is_single_val_ty)


class StructType(EMType):
    """Describe a legacy structure type."""

    def __init__(self, is_single_val_ty: bool = True) -> None:
        super().__init__(TypeKind.StructTy, is_single_val_ty)


class ArrayType(EMType):
    """Describe a legacy array type."""

    def __init__(self, is_single_val_ty: bool = True) -> None:
        super().__init__(TypeKind.ArrayTy, is_single_val_ty)


class OtherType(EMType):
    """Describe a legacy type outside the known categories."""

    def __init__(self, is_single_val_ty: bool = True) -> None:
        super().__init__(TypeKind.OtherTy, is_single_val_ty)


class TypeInference:
    """Compatibility hook for legacy expression type inference.

    The historical implementation does not infer a type for valid expressions;
    callers must treat ``None`` as unknown rather than as a scalar proof.
    """

    def __init__(self) -> None:
        pass

    @staticmethod
    def infer_type_by_expr(expr: IRExpr) -> EMType | None:
        """Validate the VEX expression boundary and return unknown type."""

        if not isinstance(expr, IRExpr):
            raise ValueError("expr is not an instance of pyvex.expr.IRExpr")
        return None
