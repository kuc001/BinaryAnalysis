import logging

from .default_cfg import CFG
from ..node.block_node import BlockNode
from .edge import CFGEdge, Kind

l = logging.getLogger(name=__name__)

class CFGBuilder:

    ID = "default_cfg"

    def analyze(self, em_program):
        """

        """
        for function in em_program.functions:
            # print(function)
            if function.cfg is None:
                cfg = CFG()
                function.initialize_cfg(cfg)
            else:
                cfg = function.cfg

            if len(cfg.get_nodes()):
                l.info("The cfg is generated before.")
                continue

            frontend_graph = function.get_frontend_graph()

            # Add node to cfg
            for node in frontend_graph.nodes():
                block = function.get_block_with_size(node.addr, node.size)
                if block is None:
                    l.warning("Node %s does not match a block.", node)
                    continue

                em_block_node = BlockNode(node.addr, node.size, ir=block.ir())
                cfg.add_node(em_block_node)

            # Add edge to cfg
            for src, dst in frontend_graph.edges():
                edge = CFGEdge(Kind.FALL_THROUGH, src, dst)
                cfg.add_edge(edge)
                # print(edge)

