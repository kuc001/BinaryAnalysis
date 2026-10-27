import logging
from .visitor import PAGVisitor
from .ir_graph import IRGraph
from .var_edge import FlowEdge, EdgeKind


l = logging.getLogger(name=__name__)


class IRGraphBuilder:

    ID = "pag"

    def __init__(self):
        self.ir_graph = IRGraph()
        self._visitor = None
    
    def set_visitor(self, visitor):
        self._visitor = visitor
        
    def build(self, em_program):
        """
        分析程序并构建程序赋值图(PAG)
        Args:
            em_program: EMProgram对象
        Returns:
            构建的PAG图
        """
        self.set_visitor(PAGVisitor(self.ir_graph))

        for function in em_program.functions:
            if not function.addr in [0x400963]:
                continue
            l.debug("Analyzing function: %s", function.name)
            cfg = function.cfg
            block_nodes = cfg.get_nodes()

            for bb_node in block_nodes:
                # if not bb_node.addr in [0x400963, 0x4009f2, 0x4009f7]:
                #     continue
                # print(bb_node)
                self._visitor.set_current_block_addr(bb_node.addr)
                self._visitor.clear_block_tmp_nodes()
                idx = 0
                first_node, last_node = None, None
                ir = bb_node.ir
                if ir is None:
                    l.warning("The IR of basic block %s is None.", bb_node)
                    continue
                ir.print_ir()
                stmt_len = len(ir.get_statements())
                for imark_stmt in ir.get_imarks():
                    self._visitor.set_current_stmt_addr(imark_stmt.addr)
                    # print(imark_stmt)
                    for stmt in imark_stmt.get_statements():
                        idx += 1
                        # print(f"{idx} | {stmt}")
                        self._visitor.set_current_stmt_idx(idx)
                        self._visitor.set_current_loc()
                        edges = self._process_statement(stmt)
                        
                        for edge in edges:
                            if idx == 1:
                                # 记录基本块入口变量节点VarNode
                                if stmt.tag == "Ist_IMark":
                                    l.warning("The first statement is IMark %s, which is not a valid statement.", stmt)
                                else:
                                    first_node = edge.get_dst()
                                    self.ir_graph.add_block_entry_node(bb_node.addr, first_node)
                        
                            if last_node is not None:
                                flow_edge = FlowEdge(last_node, edge.get_dst(), kind=EdgeKind.Flow)
                                self.ir_graph.add_edge(flow_edge)
                    
                        if len(edges) == 0:
                            l.warning("The statement %s is not processed.", stmt)
                        else:
                            last_node = edges[0].get_dst()
                        
                    # 处理imark语句
                    self._process_statement(imark_stmt)
                    idx += 1

                # 记录基本块出口变量节点VarNode
                if last_node is not None:
                    self.ir_graph.add_block_exit_node(bb_node.addr, last_node)

                # 连接当前基本块的出口节点和后序基本块的入口节点
                for succ_bb_node in bb_node.successors():
                    succ_entry_node = self.ir_graph.get_block_entry_node(succ_bb_node.addr)
                    if succ_entry_node is not None and last_node is not None:
                        edge = FlowEdge(last_node, succ_entry_node, kind=EdgeKind.Jump)
                        self.ir_graph.add_edge(edge)
                        
                # 连接当前基本块的入口节点和前序基本块的出口节点
                for pred_bb_node in bb_node.predecessors():
                    pred_exit_node = self.ir_graph.get_block_exit_node(pred_bb_node.addr)
                    if pred_exit_node is not None and first_node is not None:
                        edge = FlowEdge(pred_exit_node, first_node, kind=EdgeKind.Jump)
                        self.ir_graph.add_edge(edge)

        # for node in self.ir_graph.get_nodes():
        #     print(node)
        self.ir_graph.analyze_graph()
                  
    def _process_statement(self, stmt):
        """
        处理单条语句，将其转换为PAG中的节点和边
        Args:
            stmt: IR语句
        """
        edges = stmt.accept(self._visitor)

        return edges


    def _finalize_ir_graph(self):
        """
        处理PAG中的节点和边，添加use-def & def-use边
        """
        pass



    def _forward_analysis(self):
        """
        前向分析
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
            # l.debug(f"analyze: {node}")
            print(node)
            self.find_use(node, live_vars)
            self.add_live_vars(node, live_vars)
            for edge in node.out_edges:
                flow_node = edge.get_flow_node()
                if flow_node is not None:
                    worklist.append(flow_node)
    
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