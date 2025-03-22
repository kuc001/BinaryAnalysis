import logging
from .value import Value
from emtaint.analysis.pag.var_node import VarNode


l = logging.getLogger(name=__name__)


class UnopValue(Value):  
    def __init__(self, op, args, size, kind, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)
        
        self.op = op
        self.args = args

        self._initialize_refs()
    
    def _initialize_refs(self):
        for arg in self.args:
            if isinstance(arg, VarNode):
                name = arg.var.get_literal()
                if isinstance(name, str):
                    self.add_ref(name)
            else:
                raise l.error("The argument %s of the binop statement %s is not a VarNode.", arg, self)
    
    def __str__(self):
        if self.value is not None:
            return f"<UnopValue[{self.loc}] {self.value}>"
        else:
            return "<UnopValue[{}] {}({})".format(self.loc, self.op[4:], 
                                                   ",".join(str(a.get_literal()) for a in self.args))

    def __repr__(self):
        return self.__str__()
    
    def get_literal(self):
        return "{}".format(",".join(str(a.get_literal()) for a in self.args))
