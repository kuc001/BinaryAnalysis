import logging

from angr.serializable import Serializable


l = logging.getLogger(name=__name__)


class Function(Serializable):
    """

    """

    def __init__(
        self,
        addr,
        name=None,
        syscall=None,
        is_simprocedure: bool | None = None,
        binary_name=None,
        # is_plt: bool | None = None,
        returning=None,
        alignment=False,
        frontend_graph=None,
        cfg=None,
    ):
        self.addr = addr
        self.name = name,
        self.syscall = syscall,
        self.is_simprocedure = False,
        self.is_alignment = alignment
        self.binary_name = binary_name

        self._frontend_graph = frontend_graph   # the cfg graph is from the frontend engine (e.g., Angr, IDA, etc.)
        self.cfg = cfg

        self._returning = returning

        self._addr_to_block_node = {}  # map addresses to nodes. it's a cache of blocks. if a block is removed from the
        # function, it may not be removed from _addr_to_block_node. if you want to list
        # all blocks of a function, access .blocks.
        self._block_sizes = {}  # map addresses to block sizes
        self._local_blocks = {}  # a dict of all blocks inside the function
        self._local_block_addrs = set()  # a set of addresses of all blocks inside the function

    def get_frontend_graph(self):
        return self._frontend_graph

    def set_frontend_graph(self, graph):
        self._frontend_graph = graph

    def add_block(self, block):
        """

        """
        if block.addr and block.addr not in self._local_blocks:
            self._local_blocks[block.addr] = block
            self._local_block_addrs.add(block.addr)

    def blocks(self):
        """

        """
        for block in self._local_blocks.values():
            yield block

    def get_block(self, addr: int, size: int | None = None, byte_string: bytes | None = None):
        """
        Getting a block out of the current function.

        :param int addr:    The address of the block.
        :param int size:    The size of the block. This is optional. If not provided, angr will load
        :param byte_string:
        :return:
        """
        if addr in self._local_blocks:
            return self._local_blocks[addr]
        return None

    def get_block_with_size(self, addr: int, size: int):
        """

        """
        if addr in self._local_blocks:
            block = self._local_blocks[addr]
            if block.size != size:
                l.warning(f"The size of the target {block} does not equal the given {size}")
                return None
            return block

    def initialize_cfg(self, cfg):
        """

        """
        self.cfg = cfg
