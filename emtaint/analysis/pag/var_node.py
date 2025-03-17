

class VarNode:
    """

    """
    def __init__(self, value, kind=None):
        self.value = value
        self.kind = kind
        self.id = None      # Node ID

        self.in_edges = set()   # all incoming edge of this node
        self.out_edges = set()     # all outgoing edge of this node

