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
            if isinstance(self.addr, int):
                return f"<MemValue[{self.loc}] {self.action}(0x%x)" % self.addr
            else:
                return f"<MemValue[{self.loc}] {self.action}({self.addr})>"

    def __repr__(self):
        return self.__str__()
