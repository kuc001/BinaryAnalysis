class VarNode:
    """
    变量节点类，表示程序中的变量节点。
    
    属性:
        var: 节点的变量
        kind: 节点的类型
        id: 节点的唯一ID
        in_edges: 所有进入该节点的边
        out_edges: 所有从该节点出去的边
    """
    
    _next_id = 0  # 类变量，用于跟踪下一个可用的ID

    def __init__(self, var, ud, kind=None):
        self.var = var
        self.kind = kind
        self.id = VarNode._next_id  # 分配唯一ID
        VarNode._next_id += 1       # ID自增

        self.ues_or_def = ud  # 0: use, 1: def
        self.in_edges = set()   # 所有进入该节点的边
        self.out_edges = set()  # 所有从该节点出去的边

    def __str__(self):
        return f"<VarNode[{self.id}] {self.var}>"

    def __repr__(self):
        return self.__str__()
    
    def get_var(self):
        return self.var
    
    def add_in_edge(self, edge):
        self.in_edges.add(edge)
    
    def add_out_edge(self, edge):
        self.out_edges.add(edge)
    
    def is_use(self):
        return self.ues_or_def == 0
    
    def is_def(self):
        return self.ues_or_def == 1
    
    def set_size(self, size):
        self.var.size = size  

    def get_use_node(self):
        for edge in self.in_edges:
            if edge.is_assign() and edge.get_src().is_use():
                return edge.get_src()
        return None
    
    def with_same_value(self, node):
        return self.var.with_same_value(node.var)
    
    def get_var_literal(self):
        return self.var.get_literal()
    
    def change_var_kind(self, kind):
        self.var.kind = kind
    
    def calculate_value(self):
        """
        计算节点变量的值
        """
        pass
