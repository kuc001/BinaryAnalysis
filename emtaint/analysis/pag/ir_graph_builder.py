import logging
from .visitor import PAGVisitor
from .ir_graph import IRGraph

l = logging.getLogger(name=__name__)

class IRGraphBuilder:

    ID = "pag"

    def __init__(self):
        self.ir_graph = IRGraph()
        self._visitor = None
    
    def set_visitor(self, visitor):
        self._visitor = visitor
        
    def analyze(self, em_program):
        """
        分析程序并构建程序赋值图(PAG)
        Args:
            em_program: EMProgram对象
        Returns:
            构建的PAG图
        """
        block_info = {}
        self.set_visitor(PAGVisitor(self.ir_graph))

        for function in em_program.functions:
            l.debug(f"Analyzing function: {function.name}")
            cfg = function.cfg
            nodes = cfg.get_nodes()

            for node in nodes:
                if node.addr != 0x16FD8:
                    continue
                self._visitor.set_current_block_addr(node.addr)
                ir = node.ir
                stmt_len = len(ir.get_statements())
                for idx, stmt in enumerate(ir.get_statements()):
                    self._visitor.set_current_stmt_idx(idx)
                    self._visitor.set_current_loc()
                    edge = self._process_statement(stmt)

                    if edge is not None and idx == 0:
                        # 记录入口节点
                        self.ir_graph.add_block_entry_node(node.addr, edge.get_src())
                    elif edge is not None and idx == stmt_len - 1:
                        # 记录出口节点
                        self.ir_graph.add_block_exit_node(node.addr, edge.get_dst())

                # 连接前序基本块的出口节点和后序基本块的入口节点
                succ_node = node.successors()
                print(succ_node)

        for node in self.ir_graph.get_nodes():
            print(node)
                  
    def _process_statement(self, stmt):
        """
        处理单条语句，将其转换为PAG中的节点和边
        Args:
            stmt: IR语句
        """
        print(stmt)
        edge = stmt.accept(self._visitor)
        print(edge)

        return edge


        