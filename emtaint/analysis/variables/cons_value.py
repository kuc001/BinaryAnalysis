from .value import Value

class ConsValue(Value):
    def __init__(self, cons, size, kind, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)
        
        self.cons = cons