
from typing import List

from emtaint.assembly.block import Block
from pyvex.stmt import IRStmt
from .ir import IR

class VexIR(IR):
    """
    Default implementation of VEX IR.
    """

    def __init__(self, block: Block,
                 stmts: List[IRStmt],
                 imarks: List[IRStmt] = None):
        self.block = block
        self.stmts = stmts
        self.imarks = imarks if imarks is not None else []

    def get_block(self) -> Block:
        return self.block

    def get_statements(self):
        return self.stmts

    def get_imarks(self):
        return self.imarks
