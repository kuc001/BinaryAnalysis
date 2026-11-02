
"""Define statement-granularity nodes for the legacy control-flow graph."""

from pyvex.stmt import IRStmt

from .node import Node, repr_addr


class StmtNode(Node):
    """Associate one graph node with an ordered VEX statement sequence."""

    __slots__ = ["stmts"]

    def __init__(
        self,
        addr: int,
        size: int,
        stmts: list[IRStmt] | None,
        **kwargs: object,
    ) -> None:
        super().__init__(addr, size, **kwargs)
        self.stmts = stmts

        if not ((stmts is None and size == 0) or (stmts is not None and size == len(stmts))):
            raise ValueError('Statement node size must equal its statement count')

    def __repr__(self):
        return f"<SootBlockNode at {repr_addr(self.addr)} ({self.size} statements)>"

    def __getstate__(self):
        return self.addr, self.size, self.stmts

    def __setstate__(self, data):
        self.__init__(*data)
