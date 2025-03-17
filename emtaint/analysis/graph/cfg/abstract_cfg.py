import networkx
from collections import defaultdict
from abc import ABC, abstractmethod
from typing import Generic, TypeVar, Set, Optional, Dict

from .edge import CFGEdge

# 定义泛型类型 N
N = TypeVar('N')

class AbstractCFG(ABC, Generic[N]):
    """
    Abstract base class for Control Flow Graph (CFG).
    """

    def __init__(self):
        # self.ir = ir
        self.entry: Optional[N] = None
        self.exit: Optional[N] = None
        self.nodes: Set[N] = set()
        self.graph = networkx.DiGraph()
        self.in_edges: Dict[N, Set[CFGEdge]] = defaultdict(set)
        self.out_edges: Dict[N, Set[CFGEdge]] = defaultdict(set)

    # def get_ir(self) -> IR:
    #     """
    #     Returns the IR of the method this CFG represents.
    #     """
    #     return self.ir
    #
    # def get_method(self) -> JMethod:
    #     """
    #     Returns the method this CFG represents.
    #     """
    #     return self.ir.get_method()

    def set_entry(self, entry: N) -> None:
        """
        Sets the entry node of this CFG.
        """
        assert self.entry is None, "CFG entry should be set only once"
        self.entry = entry
        self.nodes.add(entry)

    def get_entry(self) -> Optional[N]:
        """
        Returns the entry node of this CFG.
        """
        return self.entry

    def set_exit(self, exit: N) -> None:
        """
        Sets the exit node of this CFG.
        """
        assert self.exit is None, "CFG exit should be set only once"
        self.exit = exit
        self.nodes.add(exit)

    def get_exit(self) -> Optional[N]:
        """
        Returns the exit node of this CFG.
        """
        return self.exit

    def is_entry(self, node: N) -> bool:
        """
        Returns True if the given node is the entry of this CFG, otherwise False.
        """
        return node == self.entry

    def is_exit(self, node: N) -> bool:
        """
        Returns True if the given node is the exit of this CFG, otherwise False.
        """
        return node == self.exit

    def add_node(self, node: N) -> None:
        """
        Adds a node to this CFG.
        """
        self.nodes.add(node)
        self.graph.add_node(node)

    def add_edge(self, edge: CFGEdge) -> None:
        """
        Adds an edge to this CFG.
        """
        existing_edge = self.get_existing_edge(edge)
        if existing_edge is not None:
            pass  # Implement merging logic here
        else:
            self.in_edges[edge.target].add(edge)
            self.out_edges[edge.source].add(edge)
            self.graph.add_edge(edge.source, edge.target)

    def get_existing_edge(self, edge: CFGEdge) -> Optional[CFGEdge]:
        """
        If this CFG already contains an existing edge with the same
        kind, source, and target of the given edge, returns the existing edge,
        otherwise returns None.
        """
        for out_edge in self.out_edges.get(edge.source, set()):
            if out_edge.target == edge.target and out_edge.kind == edge.kind:
                return out_edge
        return None

    def get_in_edges_of(self, node: N) -> Set[CFGEdge]:
        """
        Returns incoming edges of the given node.
        """
        return self.in_edges.get(node, set())

    def get_out_edges_of(self, node: N) -> Set[CFGEdge]:
        """
        Returns outgoing edges of the given node.
        """
        return self.out_edges.get(node, set())

    def get_preds_of(self, node: N) -> Set[N]:
        """
        Returns predecessors of the given node.
        """
        return {edge.source for edge in self.get_in_edges_of(node)}

    def get_succs_of(self, node: N) -> Set[N]:
        """
        Returns successors of the given node.
        """
        return {edge.target for edge in self.get_out_edges_of(node)}

    def get_nodes(self) -> Set[N]:
        """
        Returns all nodes in this CFG.
        """
        return self.nodes