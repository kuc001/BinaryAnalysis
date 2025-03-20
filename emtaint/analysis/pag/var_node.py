class VarNode:
    """
    变量节点类，表示程序中的变量节点。
    
    属性:
        value: 节点的值
        kind: 节点的类型
        id: 节点的唯一ID
        in_edges: 所有进入该节点的边
        out_edges: 所有从该节点出去的边
    """
    
    _next_id = 0  # 类变量，用于跟踪下一个可用的ID

    def __init__(self, value, ud, kind=None, ):
        self.value = value
        self.kind = kind
        self.id = VarNode._next_id  # 分配唯一ID
        VarNode._next_id += 1       # ID自增

        self.ues_or_def = ud  # 0: use, 1: def
        self.in_edges = set()   # 所有进入该节点的边
        self.out_edges = set()  # 所有从该节点出去的边

    def __str__(self):
        return f"<VarNode[{self.id}] {self.value}>"

    def __repr__(self):
        return self.__str__()
    
    def is_use(self):
        return self.ues_or_def == 0
    
    def is_def(self):
        return self.ues_or_def == 1
    
    def set_size(self, size):
        self.value.size = size
