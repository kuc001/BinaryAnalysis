
"""Define typed edge kinds for the legacy control-flow graph."""

from enum import Enum

from ..node.node import Node


class Kind(Enum):
    """Classify entry, branch, call, and return CFG edges."""

    ENTRY = 1   # Edge from entry node to real start node.

    FALL_THROUGH = 2    # Edge kind for fall-through to next statement.

    IF_TRUE = 3     # Edge kind for if statements when condition is true.

    IF_FALSE = 4    # Edge kind for if statements when condition is false.

    SWITCH_CASE = 5     # Edge kind for switch statements (explicit case).

    CALL = 6      # Edge kind for call statements.

    RET = 7      # Ed kind for return statements. These edges always go to the exit node of the CFG.

    FAKE_RET = 8      # Edge kind for return statements. These edges is not real return edges.


class CFGEdge:
    """Connect two legacy CFG nodes with an explicit control-flow kind."""

    def __init__(self, kind: Kind, source: Node, target: Node) -> None:
        self.kind = kind
        self.source = source
        self.target = target

    def __eq__(self, other):
        if self is other:
            return True
        if not isinstance(other, CFGEdge):
            return False
        return (self.kind == other.kind and
                self.source == other.source and
                self.target == other.target)

    def __hash__(self):
        return hash((self.kind, self.source, self.target))

    def __str__(self):
        return f"[{self.kind.name}]: {self.source} -> {self.target}"
