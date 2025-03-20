import logging
from pyvex.expr import Unop, IRExpr
from ..visitors import IRVisitor

l = logging.getLogger(name=__name__)

class Unop(Unop):
    """
    A unary operation (1 argument).
    """

    def __init__(self, op: str, args: list[IRExpr]):
        super().__init__(op, args)

    def accept(self, visitor: IRVisitor):
        return visitor.visit_unop(self)
    
    def get_size(self):
        ty = self.result_type(None)
        size = self.result_size(ty)
        return size

    def get_args_info(self):
        """
        获取操作数信息
        """
        info = []
        for arg in self.args:
            try:
                info.append(arg.get_name())
            except AttributeError:
                raise l.error("Some error occurred when processing the unop statement %s.", self)
        return info