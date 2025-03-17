
from .node import Node, repr_addr


class BlockNode(Node):
    __slots__ = ["ir"]

    def __init__(self, addr: int, size, ir=None, **kwargs):
        super().__init__(addr, size, **kwargs)
        self.ir = ir

    def __repr__(self):
        return f"<BlockNode at {repr_addr(self.addr)} (size {self.size})>"

    def __getstate__(self):
        return (self.addr, self.size, self.stmts, self.thumb)

    def __setstate__(self, dat):
        self.__init__(*dat[:-1], thumb=dat[-1])
