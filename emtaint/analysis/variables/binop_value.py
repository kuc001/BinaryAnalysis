from .value import Value

class BinopValue(Value):  
    def __init__(self, op, args, size, kind, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)
        
        self.op = op
        self.args = args

        self._initialize_refs()
    
    def _initialize_refs(self):
        for arg, _ in self.args:
            if isinstance(arg, str):
                self.add_ref(arg)
    
    def __str__(self):
        if self.value is not None:
            return f"<BinopValue[{self.loc}] {self.value}>"
        else:
            return f"<BinopValue[{self.loc}] {self.op}({self.args})>"

    def __repr__(self):
        return self.__str__()
