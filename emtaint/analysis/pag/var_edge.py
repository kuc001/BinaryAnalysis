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
    
    