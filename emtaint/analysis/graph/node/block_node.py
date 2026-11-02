
"""Define block and callee nodes for the legacy control-flow graph."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .node import _GraphView, Node, repr_addr

if TYPE_CHECKING:
    from emtaint.ir.ir import IR


class BlockNode(Node):
    """Associate a legacy code-range node with its lifted IR body."""

    __slots__ = ["ir"]

    def __init__(
        self,
        addr: int,
        size: int,
        ir: IR | None = None,
        graph: _GraphView | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(addr, size, graph=graph, **kwargs)
        self.ir = ir

    def __repr__(self):
        return f"<BlockNode at {repr_addr(self.addr)} (size {self.size})>"

    def __getstate__(self):
        return (self.addr, self.size, self.stmts, self.thumb)

    def __setstate__(self, dat):
        self.__init__(*dat[:-1], thumb=dat[-1])


class CalleeNode(BlockNode):
    """Describe a call target and its syscall or SimProcedure classification."""

    __slots__ = ["name", "is_syscall", "is_simprocedure", "simprocedure_name"]

    def __init__(
        self,
        addr: int,
        size: int,
        ir: IR | None = None,
        graph: _GraphView | None = None,
        name: str | None = None,
        is_syscall: bool = False,
        is_simprocedure: bool = False,
        simprocedure_name: str | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(addr, size, ir=ir, graph=graph, **kwargs)
        self.name = name
        self.is_syscall = is_syscall
        self.is_simprocedure = is_simprocedure
        self.simprocedure_name = simprocedure_name

    def __repr__(self):
        return f"<CalleeNode at {repr_addr(self.addr)} (size {self.size})>"
