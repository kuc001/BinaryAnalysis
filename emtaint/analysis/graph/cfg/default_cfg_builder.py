import logging
from typing import Optional

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
                em_block_node = self.add_node(node, function, cfg)
                if em_block_node is None:
                    continue

                succ_nodes = node.successors()
                for succ_node in succ_nodes:
                    em_succ_node = self.add_node(succ_node, function, cfg)
                    if em_succ_node is None:
                        continue

                    edge = CFGEdge(Kind.FALL_THROUGH, em_block_node, em_succ_node)
                    cfg.add_edge(edge)

    def add_node(self, node, function, cfg) -> Optional[BlockNode]:
        """
        Adds a node to this CFG.
        Args:
            node: 要添加的节点
        Returns:
            添加的节点
        """
        if cfg.has_node(node):
            return cfg.get_node(node.addr)
        
        block = function.get_block_with_size(node.addr, node.size)
        if block is None:
            l.warning("Node %s does not match a block.", node)
            return None

        em_block_node = BlockNode(node.addr, node.size, ir=block.ir(), graph=cfg.graph)
        cfg.add_node(em_block_node)
        return em_block_node