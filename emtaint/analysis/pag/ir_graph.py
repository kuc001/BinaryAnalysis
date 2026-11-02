"""Own legacy program-assignment graph nodes, edges, and traversal state."""

import logging
from uuid import uuid4
from .var_node import VarNode
from emtaint.analysis.variables.reg_value import RegValue
from emtaint.analysis.variables.mem_value import MemValue


l = logging.getLogger(name=__name__)
l.setLevel(logging.DEBUG)


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
        self._node_scope = uuid4().hex
        self._next_node_id = 0

        self.function_entry_nodes = {} # 记录每个函数入口节点
        self.function_exit_nodes = {} # 记录每个函数出口节点
        self.block_entry_nodes = {} # 记录每个块入口节点
        self.block_exit_nodes = {} # 记录每个块出口节点
    
    def new_node(self, var, ud, kind=None):
        node = VarNode(var, ud, kind, node_id=self._next_node_id, owner=self._node_scope)
        self._next_node_id += 1
        return node

    def add_node(self, id, node):
        """添加节点并自动分配ID
        
        Args:
            id: 节点的ID
            node: 要添加的节点
        Returns:
            分配给节点的ID
        """
        if node._owner is not None and node._owner != self._node_scope:
            raise ValueError('PAG node belongs to another graph')
        if id != node.id:
            raise ValueError('Node map key differs from the node ID')
        if id in self.id_to_node_map:
            if self.id_to_node_map[id] is not node:
                raise ValueError('Duplicate PAG node ID')
            return id
        node._owner = self._node_scope
        self.id_to_node_map[id] = node
        self._next_node_id = max(self._next_node_id, id + 1)
        self.node_num += 1
        return id

    def get_node(self, id):
        return self.id_to_node_map.get(id)

    def get_nodes(self):
        return list(self.id_to_node_map.values())
    
    def add_edge(self, edge):
        edge.get_src().add_out_edge(edge)
        edge.get_dst().add_in_edge(edge)
    
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
    
    def analyze_graph(self, entry_block_addrs=None):
        """
        分析图
        """
        addresses = tuple(self.block_entry_nodes) if entry_block_addrs is None else tuple(entry_block_addrs)
        # Empty graphs are valid; an explicit missing entry is an error.
        worklist = [self.block_entry_nodes[address] for address in addresses]
        visited = set()
        live_vars = {}
        while worklist:
            node = worklist.pop()
            if node in visited:
                continue
            visited.add(node)
            # l.debug(f"analyze: {node}")
            print(node)
            # self.find_use(node, live_vars)
            # self.add_live_vars(node, live_vars)
            for edge in node.out_edges:
                flow_node = edge.get_flow_node()
                if flow_node is not None:
                    worklist.append(flow_node)
        return frozenset(visited)
    
    def add_live_vars(self, node, live_vars):
        """
        """
        if node.is_use():
            live_vars[node.id] = node
        elif node.is_def():
            # self.kill_live_vars(node, live_vars)
            live_vars[node.id] = node
            for edge in node.out_edges:
                use_node = edge.get_use()
                if use_node is not None:
                    live_vars[use_node.id] = use_node
    
    def find_def(self, use_node, live_vars):
        """
        找到use_node的def节点, 并连接use_node和def_node
        """
        for var_id in live_vars.keys():
            live_node = live_vars[var_id]
            if live_node.is_def() and live_node.value.name == use_node.value.name:
                return live_node
    
    def find_use(self, node, live_vars):
        """
        找到node的use节点, 并连接node和use_node
        kind: 
            use -> use
            def -> use
        """
        if node.is_use():
            use_node = node
        else:
            use_node = node.get_use_node()
        if use_node is None:
            return
        
        for var_id in live_vars.keys():
            live_node = live_vars[var_id]
            if live_node.with_same_value(use_node):
                l.debug(f"find use node: {use_node}, live_node: {live_node}")
                # self.add_edge(node, live_node)

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

    
  

    def exec_stmt(self, edge):
        """
        执行stmt, 并返回stmt的输出
        """
        from emtaint.compat.legacy_pag import execute_edge
        return execute_edge(edge)


