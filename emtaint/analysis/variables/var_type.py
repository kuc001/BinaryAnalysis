from typing import Optional
from enum import IntEnum
from pyvex.expr import IRExpr

class TypeKind(IntEnum):
    EMType = 0
    PointerTy = 1
    IntegerTy = 2
    FunctionTy = 3
    StructTy = 4
    ArrayTy = 5
    OtherTy = 6

class EMType:
    """
    EMType class implementation
    """
    def __init__(self, kind: TypeKind=None, is_single_val_ty: bool=True):
        self._kind: int = kind                    
        # self._typeinfo = None                     
        self._is_single_val_ty: bool = is_single_val_ty  # 类型是否表示单个值（非结构体或数组）
    
    @property
    def kind(self) -> int:
        return self._kind
    
    # @property
    # def typeinfo(self):
    #     return self._typeinfo
    
    def is_single_val_ty(self) -> bool:
        return self._is_single_val_ty
    

class PointerType(EMType):
    """
    PointerType class implementation
    """
    def __init__(self, is_single_val_ty: bool=True):
        super().__init__(TypeKind.PointerTy, is_single_val_ty)

class IntegerType(EMType):
    """
    IntegerType class implementation
    """
    def __init__(self, is_single_val_ty: bool=True):
        super().__init__(TypeKind.IntegerTy, is_single_val_ty)

class FunctionType(EMType):
    """
    FunctionType class implementation
    """
    def __init__(self, is_single_val_ty: bool=True):
        super().__init__(TypeKind.FunctionTy, is_single_val_ty)

class StructType(EMType):
    """
    StructType class implementation
    """
    def __init__(self, is_single_val_ty: bool=True):
        super().__init__(TypeKind.StructTy, is_single_val_ty)

class ArrayType(EMType):
    """
    ArrayType class implementation  
    """
    def __init__(self, is_single_val_ty: bool=True):
        super().__init__(TypeKind.ArrayTy, is_single_val_ty)

class OtherType(EMType):
    """ 
    OtherType class implementation
    """
    def __init__(self, is_single_val_ty: bool=True):
        super().__init__(TypeKind.OtherTy, is_single_val_ty)

class TypeInference:
    """
    TypeInference class implementation
    """
    def __init__(self):
        pass
    
    @staticmethod
    def infer_type_by_expr(expr: IRExpr) -> EMType:
        if not isinstance(expr, pyvex.expr.IRExpr):
            raise ValueError("expr is not an instance of pyvex.expr.IRExpr")
        
        

