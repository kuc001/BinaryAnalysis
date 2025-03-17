import logging
import time

from .block_ir_builder import BlockIRBuilder


l = logging.getLogger(name=__name__)


class IRBuilder:
    """

    """

    def build_ir(self, block):
        """
        Build IR for EmTaint in the given block.
        :param block: the EmTaint's Block in program
        """
        return BlockIRBuilder(block).build()

    def build_all(self, cfg):
        time_start = time.time()

        # for func in cfg.kb.functions.values():
        #     func_builder = FunctionBuilder(func)
        #     func_builder.build()

        time_end = time.time()
        print(f"Build IR for cfg cost: %lf" % (time_end-time_start))



