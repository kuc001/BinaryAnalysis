from .value import Value

class MemValue(Value):
    def __init__(self, addr, size, kind, action, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)
        
        self.addr = addr
        self.action = action

    def __str__(self):
        if self.value is not None:
            return f"<MemValue[{self.loc}] {self.value}>"
        else:
            if isinstance(self.addr, Value):
                return f"<MemValue[{self.loc}] {self.action}({self.addr.get_literal()})>"
            else:
                raise ValueError(f"The address of the mem value {self} is not a VarNode.")

    def __repr__(self):
        return self.__str__()
