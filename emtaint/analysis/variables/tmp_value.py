from .value import Value, ValueKind

class TmpValue(Value):
    def __init__(self, name, size, kind, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)

        self.name = name    # 临时变量名

        self.add_ref(name)
        
    def __str__(self):
        if self.value is not None:
            return f"<TmpValue[{self.loc}] {self.value}>"
        else:
            return f"<TmpValue[{self.loc}] {self.name}>"

    def __repr__(self):
        return self.__str__()
    
    def get_literal(self):
        return self.name