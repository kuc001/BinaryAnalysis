
from emtaint.assembly.function import Function
from emtaint.assembly.block import Block

# Converts Angr functions to TmTaint's representation.
class Converter:
    """
    负责将angr的函数、基本块转换为EmTaint的函数和基本块
    """
    def __init__(self, project, cfg):

        self._project = project
        self._cfg = cfg

    def convert_function(self, function):
        em_function = Function(function.addr)
        em_function.name = function.name


        return em_function

    def convert_block(self, block, ir_builder):
        em_block = Block(block.addr, block.size, block.bytes, block_source=block)
        ir = ir_builder.build_ir(em_block)
        em_block.set_ir(ir)
        return em_block
