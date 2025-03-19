from enum import IntEnum
from .var_node import VarNode


class EdgeKind(IntEnum):
    Assign = 0  # 赋值
    StoreAssign = 1 # 存储赋值
    LoadAssign = 2 # 加载赋值
    BinopAssign = 3 # 二元运算赋值
    UnaryopAssign = 4 # 一元运算赋值
    Call = 5   # 调用
    Return = 6 # 返回
    Phi = 7    # Phi
    Branch = 8 # 分支
    Jump = 9   # 跳转
    

class VarEdge:
    """
    变量边类，表示程序中的变量边。
    
    属性:
        src: 边的源节点
        dst: 边的目标节点
        kind: 边类型
        stmt: 边对应的语句
    """
    def __init__(self, src: VarNode, dst: VarNode, kind = None, stmt = None):
        self.src = src
        self.dst = dst
        self.kind = kind
        self.stmt = stmt
    
    def get_src(self):
        return self.src
    
    def get_dst(self):
        return self.dst
    
    