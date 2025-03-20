from .value import Value

class UnopValue(Value):  
    def __init__(self, op, args, size, kind, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)
        
        self.op = op
        self.args = args

        self._initialize_refs()
    
    def _initialize_refs(self):
        for arg in self.args:
            if isinstance(arg, str):
                self.add_ref(arg)
    
    def __str__(self):
        if self.value is not None:
            return f"<UnopValue[{self.loc}] {self.value}>"
        else:
            return "<UnopValue[{}] {}({})".format(self.loc, self.op[4:], 
                                                   ",".join(str(a.value.get_literal()) for a in self.args))

    def __repr__(self):
        return self.__str__()
