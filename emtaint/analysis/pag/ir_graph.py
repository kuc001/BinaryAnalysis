class IRGraph:
    """IR图的基类实现
    
    属性:
        id_to_node_map: 节点ID到节点的映射
        edge_num: 边的数量
        node_num: 节点的数量
        next_id: 下一个可用的节点ID
    """
    def __init__(self):
        self.id_to_node_map = {}
        self.edge_num = 0
        self.node_num = 0

        self.function_entry_nodes = {} # 记录每个函数入口节点
        self.function_exit_nodes = {} # 记录每个函数出口节点
        self.block_entry_nodes = {} # 记录每个块入口节点
        self.block_exit_nodes = {} # 记录每个块出口节点
    
    def add_node(self, id, node):
        """添加节点并自动分配ID
        
        Args:
            id: 节点的ID
            node: 要添加的节点
        Returns:
            分配给节点的ID
        """
        self.id_to_node_map[id] = node
        self.node_num += 1
        return id

    def get_node(self, id):
        return self.id_to_node_map.get(id)

    def get_nodes(self):
        return list(self.id_to_node_map.values())
    
    def add_block_entry_node(self, block_addr, node):
        self.block_entry_nodes[block_addr] = node
    
    def add_block_exit_node(self, block_addr, node):
        self.block_exit_nodes[block_addr] = node
        
