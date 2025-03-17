from .value import Value

class MemValue(Value):
    def __init__(self, ty, kind, value=None, loc=None, expr=None):
        super().__init__(ty, kind, value, loc, expr)
        
        self.base = None
        self.offset = None
        self.size = None
        self.is_stack = False
        self.is_heap = False
        self.is_global = False
        