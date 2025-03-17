import logging
from .visitor import PAGVisitor

l = logging.getLogger(name=__name__)

class IRGraphBuilder:

    ID = "pag"

    def __init__(self):
        self._visitor = PAGVisitor()
        
    def analyze(self, em_program):
        """
        分析程序并构建程序赋值图(PAG)
        Args:
            em_program: EMProgram对象
        Returns:
            构建的PAG图
        """
        for function in em_program.functions:
            l.debug(f"Analyzing function: {function.name}")
            cfg = function.cfg
            nodes = cfg.get_nodes()

            for node in nodes:
                if node.addr != 0x16FD8:
                    continue
                ir = node.ir
                for stmt in ir.get_statements():
                    self._process_statement(stmt)
                  
    def _process_statement(self, stmt):
        """
        处理单条语句，将其转换为PAG中的节点和边
        Args:
            stmt: IR语句
        """
        print(stmt)
        stmt.accept(self._visitor)

        