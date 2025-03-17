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
