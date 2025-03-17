

class IRGraph:
    """

    """
    def __init__(self):

        self.id_to_node_map = {}
        self.edge_num = 0
        self.node_num = 0

    def add_node(self, id, node):
        if id not in self.id_to_node_map:
            self.id_to_node_map[id] = node
            self.node_num += 1

    def get_node(self, id):
        return self.id_to_node_map.get(id)