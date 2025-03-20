from emtaint.analysis.variables.reg_value import RegValue
from emtaint.analysis.variables.mem_value import MemValue

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
    
    def has_block_entry_node(self, block_addr):
        return block_addr in self.block_entry_nodes
    
    def has_block_exit_node(self, block_addr):
        return block_addr in self.block_exit_nodes
    
    def get_block_entry_node(self, block_addr):
        return self.block_entry_nodes.get(block_addr)
    
    def get_block_exit_node(self, block_addr):
        return self.block_exit_nodes.get(block_addr)
    
    def analyze_graph(self):
        """
        分析图
        """
        worklist = []
        visited = set()
        live_vars = {}
        start_node = self.get_block_entry_node(0x16fd8)
        worklist.append(start_node)
        while worklist:
            node = worklist.pop()
            if node in visited:
                continue
            visited.add(node)
            print(node)
            self.add_live_vars(node, live_vars)
            for edge in node.out_edges:
                worklist.append(edge.get_dst())
    
    def add_live_vars(self, node, live_vars):
        """
        """
        if node.is_use():
            live_vars[node.id] = node
        elif node.is_def():
            self.kill_live_vars(node, live_vars)
            live_vars[node.id] = node

    def kill_live_vars(self, node, live_vars):
        """
        case one: register def, e.g., r1 = r2
        case two: memory store def, e.g., store(r1+offset) = r2
        """
        keys = list(live_vars.keys())
        for var_id in keys:
            live_node = live_vars[var_id]

            if isinstance(node.value, RegValue) and isinstance(live_node.value, RegValue):
                if node.value.name == live_node.value.name:
                    live_vars.pop(var_id)
            elif isinstance(node.value, MemValue) and isinstance(live_node.value, MemValue):
                if node.value.addr == live_node.value.addr:
                    live_vars.pop(var_id)

        