import logging
from .visitor import PAGVisitor
from .ir_graph import IRGraph
from .var_edge import VarEdge, EdgeKind


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
            l.debug("Analyzing function: %s", function.name)
            cfg = function.cfg
            block_nodes = cfg.get_nodes()

            for bb_node in block_nodes:
                if bb_node.addr != 0x16FD8:
                    continue
                # print(bb_node)
                self._visitor.set_current_block_addr(bb_node.addr)
                idx = 0
                first_node, last_node = None, None
                ir = bb_node.ir
                if ir is None:
                    l.warning("The IR of basic block %s is None.", bb_node)
                    continue
                # ir.print_ir()
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
                                    first_node = edge.get_src()
                                    self.ir_graph.add_block_entry_node(bb_node.addr, edge.get_src())
                        
                            if last_node is not None:
                                flow_edge = VarEdge(last_node, edge.get_src(), kind=EdgeKind.Flow)
                                edge.get_src().in_edges.add(flow_edge)
                                last_node.out_edges.add(flow_edge)
                    
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
                        edge = VarEdge(last_node, succ_entry_node, kind=EdgeKind.Jump)
                        last_node.out_edges.add(edge)
                        succ_entry_node.in_edges.add(edge)
                        
                
                # 连接当前基本块的入口节点和前序基本块的出口节点
                for pred_bb_node in bb_node.predecessors():
                    pred_exit_node = self.ir_graph.get_block_exit_node(pred_bb_node.addr)
                    if pred_exit_node is not None and first_node is not None:
                        edge = VarEdge(pred_exit_node, first_node, kind=EdgeKind.Jump)
                        pred_exit_node.out_edges.add(edge)
                        first_node.in_edges.add(edge)

        for node in self.ir_graph.get_nodes():
            print(node)
        # self.ir_graph.analyze_graph()
                  
    def _process_statement(self, stmt):
        """
        处理单条语句，将其转换为PAG中的节点和边
        Args:
            stmt: IR语句
        """
        edges = stmt.accept(self._visitor)

        return edges


        