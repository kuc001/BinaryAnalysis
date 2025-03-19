
from .abstract_cfg import AbstractCFG
from ..node.block_node import BlockNode

class CFG(AbstractCFG[BlockNode]):
    def __init__(self):
        super().__init__()

