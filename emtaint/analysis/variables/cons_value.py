from .value import Value

class ConsValue(Value):
    def __init__(self, cons, size, kind, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)
        
        self.cons = cons

    def __str__(self):
        if self.value is not None:
            return f"<ConsValue[{self.loc}] {self.value}>"
        else:
            return f"<ConsValue[{self.loc}] {self.cons}>"

    def __repr__(self):
        return self.__str__()