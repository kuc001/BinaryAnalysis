from enum import IntEnum

class ValueKind(IntEnum):
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
    """
    Value类是数据流分析中值的基类。
    
    属性:
        kind: 值的种类
        size: 值的大小
        value: 使用claripy表示的值(可选)
        ty: 变量（值变量或指针变量指向的对象）的类型(可选)
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
    
    def get_literal(self):
        return None
    
    def get_value(self):
        return self.value
    
    def get_type(self):
        return self.type
    
    def with_same_value(self, other):
        if self.value is not None and other.value is not None:
            return self.value == other.value and self.kind == other.kind
        return False
