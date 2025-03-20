
from .node import Node, repr_addr


class BlockNode(Node):
    __slots__ = ["ir"]

    def __init__(self, addr: int, size, ir=None, graph=None, **kwargs):
        super().__init__(addr, size, graph=graph, **kwargs)
        self.ir = ir

    def __repr__(self):
        return f"<BlockNode at {repr_addr(self.addr)} (size {self.size})>"

    def __getstate__(self):
        return (self.addr, self.size, self.stmts, self.thumb)

    def __setstate__(self, dat):
        self.__init__(*dat[:-1], thumb=dat[-1])


class CalleeNode(BlockNode):
    __slots__ = ["name", "is_syscall", "is_simprocedure", "simprocedure_name"]

    def __init__(self, addr: int, size, 
                 ir=None, 
                 graph=None, 
                 name=None, 
                 is_syscall=False, 
                 is_simprocedure=False, 
                 simprocedure_name=None, 
                 **kwargs):
        super().__init__(addr, size, ir=ir, graph=graph, **kwargs)
        self.name = name
        self.is_syscall = is_syscall
        self.is_simprocedure = is_simprocedure
        self.simprocedure_name = simprocedure_name

    def __repr__(self):
        return f"<CalleeNode at {repr_addr(self.addr)} (size {self.size})>"
