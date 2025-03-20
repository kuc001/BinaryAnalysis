import logging
from typing import List
from pyvex import IRSB
from pyvex.stmt import IRStmt

from emtaint.assembly.block import Block
from .ir import IR

l = logging.getLogger(name=__name__)

class VexIR(IR):
    """
    Default implementation of VEX IR.
    """

    def __init__(self, block: Block,
                 stmts: List[IRStmt],
                 imarks: List[IRStmt] = None,
                 vex: IRSB = None):
        self.block = block
        self.stmts = stmts
        self.imarks = imarks if imarks is not None else []

        self._vex = vex

    def set_vex(self, vex: IRSB):
        if self._vex is not None:
            l.warning("VEX IR is already set for block: %s", self.block)
        self._vex = vex
    
    def get_vex(self):
        return self._vex

    def get_block(self) -> Block:
        return self.block

    def get_statements(self):
        return self.stmts

    def get_imarks(self):
        return self.imarks
    
    def print_stmts(self):
        print(f"block: {self.block}")
        for stmt in self.stmts:
            print(stmt)
    
    def print_ir(self):
        if self._vex is not None:
            self._vex.pp()
        else:
            l.warning("VEX IR is not set for block: %s", self.block)
