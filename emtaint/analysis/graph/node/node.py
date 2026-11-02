"""Define graph-owned address nodes for the legacy CFG implementation."""

from __future__ import annotations

from collections.abc import Iterable
from typing import Protocol
import weakref

from emtaint.assembly.block import Block


class _GraphView(Protocol):
    """Minimal graph navigation used by a legacy node."""

    def successors(self, node: Node) -> Iterable[Node]:
        """Iterate nodes reached by outgoing edges."""

        ...

    def predecessors(self, node: Node) -> Iterable[Node]:
        """Iterate nodes reached by incoming edges."""

        ...


def repr_addr(addr: object) -> str:
    """Format integer addresses as hexadecimal and other identities by repr."""

    if isinstance(addr, int):
        return hex(addr)
    return repr(addr)


class Node:
    """Represent one graph-owned code range and its instruction-set mode."""

    __slots__ = ["_graph", "_hash", "addr", "size", "thumb"]

    def __init__(
        self,
        addr: int,
        size: int,
        graph: _GraphView | None = None,
        thumb: bool = False,
    ) -> None:
        self.addr: int = addr
        self.size: int = size
        self.thumb = thumb
        self._graph = weakref.proxy(graph) if graph is not None else None

        self._hash = None

    def __len__(self):
        return self.size

    def __eq__(self, other):
        if type(other) is Block:  # pylint: disable=unidiomatic-typecheck
            raise TypeError("You do not want to be comparing a CFG Node to a assembly Block")
        return (
            type(self) is type(other)
            and self.addr == other.addr
            and self.size == other.size
            and self.thumb == other.thumb
        )

    def __ne__(self, other):
        return not self == other

    def __cmp__(self, other):
        raise TypeError("Comparison with a code node")

    def __hash__(self):
        if self._hash is None:
            self._hash = hash((self.addr, self.size))
        return self._hash

    def set_graph(self, graph: _GraphView) -> None:
        """Attach the node to the graph that owns its navigation queries."""

        self._graph = weakref.proxy(graph)

    def successors(self) -> list[Node]:
        """Return immediate successors from the owning graph."""

        if self._graph is None:
            raise ValueError("Cannot calculate successors for graphless node")
        return list(self._graph.successors(self))
    
    def predecessors(self) -> list[Node]:
        """Return immediate predecessors from the owning graph."""

        if self._graph is None:
            raise ValueError("Cannot calculate predecessors for graphless node")
        return list(self._graph.predecessors(self))

    def __getstate__(self):
        return (self.addr, self.size)

    def __setstate__(self, dat):
        self.__init__(*dat)
