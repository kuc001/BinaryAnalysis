
from typing import List

from emtaint.assembly.block import Block
from pyvex.stmt import IRStmt
from .ir import IR

class VexIR(IR):
    """
    Default implementation of VEX IR.
    """

    def __init__(self, block: Block,
                 statements: List[IRStmt]):
        self.block = block
        self.statements = statements

    def get_block(self) -> Block:
        return self.block

    def get_statements(self):
        return self.statements