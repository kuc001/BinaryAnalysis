import logging
from typing import Optional
from angr.knowledge_plugins.functions import Function as AngrFunction

from .default_cfg import CFG
from ..node.block_node import BlockNode, CalleeNode
from .edge import CFGEdge, Kind

l = logging.getLogger(name=__name__)

class CFGBuilder:

    ID = "default_cfg"

    def analyze(self, em_program):
        """
        Build the CFG for the given em_program.
        Args:
            em_program: 要分析的program
        """
        for function in em_program.functions:
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
                
                has_callee, callee_node = False, None
                em_succ_nodes = []
                succ_nodes = node.successors()
                for succ_node in succ_nodes:
                    em_succ_node = self.add_node(succ_node, function, cfg)
                    if em_succ_node is None:
                        continue

                    if isinstance(em_succ_node, CalleeNode):
                        has_callee = True
                        callee_node = em_succ_node
                    else:
                        em_succ_nodes.append(em_succ_node)
                
                if has_callee:
                    call_edge = CFGEdge(Kind.CALL, em_block_node, callee_node)
                    cfg.add_edge(call_edge)

                    if len(em_succ_nodes) == 1:
                        ret_edge = CFGEdge(Kind.RET, callee_node, em_succ_nodes[0])
                        cfg.add_edge(ret_edge)

                        fake_edge = CFGEdge(Kind.FAKE_RET, em_block_node, em_succ_nodes[0])
                        cfg.add_edge(fake_edge)
                    else:
                        l.warning("The callee node %s -> %s has multiple return successors.", node, callee_node)
                    
                else:
                    for em_succ_node in em_succ_nodes:
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
        
        if isinstance(node, AngrFunction):
            em_block_node = CalleeNode(node.addr, node.size, 
                                       graph=cfg.graph, 
                                       name=node.name, 
                                       is_syscall=node.is_syscall, 
                                       is_simprocedure=node.is_simprocedure)
            cfg.add_node(em_block_node)
            return em_block_node

        block = function.get_block_with_size(node.addr, node.size)
        if block is None:
            l.warning("Node %s does not match a block.", node)
            return None

        em_block_node = BlockNode(node.addr, node.size, ir=block.ir(), graph=cfg.graph)
        cfg.add_node(em_block_node)
        return em_block_node