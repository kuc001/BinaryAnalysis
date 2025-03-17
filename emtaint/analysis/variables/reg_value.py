from .value import Value

class RegValue(Value):
    def __init__(self, name, size, kind, value=None, ty=None, loc=None, expr=None):
        super().__init__(kind, size, value, ty, loc, expr)

        self.name = name    # 寄存器名

        self.add_ref(name)
            