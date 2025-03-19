from pyvex.expr import Binop    
from ..visitors import IRVisitor

class Binop(Binop):
    """
    A binary operation (2 arguments).
    """
    
    def __init__(self, op, args, op_int=None):
        super().__init__(op, args, op_int)
    
    def accept(self, visitor: IRVisitor):
        return visitor.visit_binop(self)

    def get_size(self):
        return self.result_size(self.op)
    
    def get_args_info(self):
        """
        获取操作数信息
        """
        info = []
        for arg in self.args:
            try:
                info.append((arg.get_name(), arg.get_size()))
            except AttributeError:
                info.append((arg.get_name(), self.get_size()))
        return info