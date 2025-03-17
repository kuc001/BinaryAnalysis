
from enum import Enum

class Kind(Enum):
    ENTRY = 1   # Edge from entry node to real start node.

    FALL_THROUGH = 2    # Edge kind for fall-through to next statement.

    GOTO = 3    # Edge kind for goto statements.

    IF_TRUE = 4     # Edge kind for if statements when condition is true.

    IF_FALSE = 5    # Edge kind for if statements when condition is false.

    SWITCH_CASE = 6     # Edge kind for switch statements (explicit case).

    RETURN = 7      # dge kind for return statements. These edges always go to the exit node of the CFG.


class CFGEdge:
    def __init__(self, kind: Kind, source, target):
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
