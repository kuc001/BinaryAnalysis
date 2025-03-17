from enum import IntEnum

class ValueKind(IntEnum):
    Const = 0
    Global = 1
    Array = 2
    Struct = 3
    Pointer = 4
    StackPtr = 5
    StackAccess = 6
    MemAccess = 7
    ArrayAccess = 8
    StructAccess = 9
    FunctionPtr = 10
    Unknown = 11

class Value:
    """
    Value类是数据流分析中值的基类。
    
    属性:
        kind: 值的种类
        size: 值的大小
        value: 使用claripy表示的值(可选)
        ty: 值的类型(可选)
        loc: 值的位置(可选)
        expr: IR表达式(可选)
    """
    def __init__(self, kind: ValueKind, size, value=None, ty=None, loc=None, expr=None):
        self.kind = kind
        self.size = size
        self.value = value
        self.type = ty
        self.loc = loc
        self._expr = expr

        self.refs = set()
        
    def __str__(self):
        return f"{self.kind} {self.value}"

    def __repr__(self):
        return self.__str__()
    
    def add_ref(self, ref):
        self.refs.add(ref)
    