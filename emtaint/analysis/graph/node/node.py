import weakref
from emtaint.assembly.block import Block

def repr_addr(addr):
    if isinstance(addr, int):
        return hex(addr)
    return repr(addr)


class Node:
    __slots__ = ["_graph", "_hash", "addr", "size", "thumb"]

    def __init__(self, addr: int, size: int, graph=None, thumb=False):
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

    def set_graph(self, graph):
        self._graph = weakref.proxy(graph)

    def successors(self):
        if self._graph is None:
            raise ValueError("Cannot calculate successors for graphless node")
        return list(self._graph.successors(self))
    
    def predecessors(self):
        if self._graph is None:
            raise ValueError("Cannot calculate predecessors for graphless node")
        return list(self._graph.predecessors(self))

    def __getstate__(self):
        return (self.addr, self.size)

    def __setstate__(self, dat):
        self.__init__(*dat)
