from .value import Value, ValueKind

class TmpValue(Value):
    def __init__(self, name, size, kind, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)

        self.name = name    # 临时变量名

        self.add_ref(name)
        
        