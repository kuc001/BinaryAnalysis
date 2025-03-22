from enum import IntEnum
from .var_node import VarNode


class EdgeKind(IntEnum):
    # 赋值边
    Assign = 0  # 赋值
    AssignIfTrue = 1 # 赋值（if true）
    AssignIfFalse = 2 # 赋值（if false）
    StoreAssign = 3 # 存储赋值
    LoadAssign = 4 # 加载赋值
    BinopAssign = 5 # 二元运算赋值
    UnaryopAssign = 6 # 一元运算赋值

    # 操作数边, 也属于赋值边，但不对应具体的语句
    Binop = 7 # 二元运算
    Unaryop = 8 # 一元运算
    Addr = 9 # 地址

    # 控制流边
    Flow = 10 # 控制流
    Jump = 11 # 跳转
    Call = 12 # 调用
    Ret = 13 # 返回
    FakeRet = 14 # 假返回
    
    

class VarEdge:
    """
    变量边类，表示程序中的变量边。
    
    属性:
        src: 边的源节点
        dst: 边的目标节点
        kind: 边类型
        stmt: 边对应的语句
    """
    def __init__(self, src: VarNode, dst: VarNode, kind = None, guard = None, stmt = None):
        self.src = src
        self.dst = dst
        self.kind = kind
        self.guard = guard
        self.stmt = stmt
    
    def get_src(self):
        return self.src
    
    def get_dst(self):
        return self.dst
    
    def is_assign(self):
        return self.kind <= EdgeKind.UnaryopAssign and self.kind >= EdgeKind.Assign
    
    def get_use(self):
        if self.src.is_use() and self.is_assign():
            return self.src
        return None

    def get_def(self):
        if self.dst.is_def() and self.is_assign():
            return self.dst
        return None
    
    def get_flow_node(self):
        if self.kind >= EdgeKind.Flow and self.kind <= EdgeKind.FakeRet:
            return self.dst
        return None


class AssignEdge(VarEdge):
    """
    赋值边类，表示程序中的赋值边。
    
    """
    tag = "Assign"
    def __init__(self, src: VarNode, dst: VarNode, kind = None, guard = None, stmt = None):
        super().__init__(src, dst, kind, guard, stmt)

class FlowEdge(VarEdge):
    """
    控制流边类，表示程序中的控制流边。
    
    """
    tag = "Flow"
    def __init__(self, src: VarNode, dst: VarNode, kind = None, guard = None, stmt = None):
        super().__init__(src, dst, kind, guard, stmt)

class OpEdge(VarEdge):
    """
    操作数边类，表示程序中的操作数边。
    
    """
    tag = "Op"
    def __init__(self, src: VarNode, dst: VarNode, kind = None, guard = None, stmt = None, op_idx = None):
        super().__init__(src, dst, kind, guard, stmt)
        self.op_idx = op_idx


class AddrEdge(VarEdge):
    """
    地址边类，表示程序中的地址边。
    
    """
    tag = "Addr"
    def __init__(self, src: VarNode, dst: VarNode, kind = None, guard = None, stmt = None):
        super().__init__(src, dst, kind, guard, stmt)
