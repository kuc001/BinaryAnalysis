

class StmtNode(Node):
    __slots__ = ["stmts"]

    def __init__(self, addr, size, stmts, **kwargs):
        super().__init__(addr, size, **kwargs)
        self.stmts = stmts

        assert (stmts is None and size == 0) or (size == len(stmts))

    def __repr__(self):
        return f"<SootBlockNode at {repr_addr(self.addr)} ({self.size} statements)>"

    def __getstate__(self):
        return self.addr, self.size, self.stmts

    def __setstate__(self, data):
        self.__init__(*data)