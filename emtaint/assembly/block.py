"""
This file is from Angr.
"""

from __future__ import annotations
import logging
from typing import TYPE_CHECKING

import pyvex
from pyvex import IRSB
from archinfo import Arch, ArchARM

from angr.protos import primitives_pb2 as pb2
from angr.serializable import Serializable

try:
    from angr.engines import pcode
except ImportError:
    pcode = None

if TYPE_CHECKING:
    from angr import Project
    from angr.engines.vex import VEXLifter
    from angr.engines.pcode.lifter import PcodeLifterEngineMixin, IRSB as PcodeIRSB
    from angr.engines.soot.engine import SootMixin


l = logging.getLogger(name=__name__)


class DisassemblerBlock:
    """
    Helper class to represent a block of disassembled target architecture
    instructions
    """

    __slots__ = ["addr", "arch", "insns", "thumb"]

    def __init__(self, addr, insns, thumb, arch):
        self.addr = addr
        self.insns = insns
        self.thumb = thumb
        self.arch = arch

    def pp(self):
        print(str(self))

    def __str__(self):
        return "\n".join(str(x) for x in self.insns)

    def __repr__(self):
        return f"<DisassemblerBlock for {self.addr:#x}>"


class DisassemblerInsn:
    """
    Helper class to represent a disassembled target architecture instruction
    """

    __slots__ = ()

    @property
    def size(self) -> int:
        raise NotImplementedError

    @property
    def address(self) -> int:
        raise NotImplementedError

    @property
    def mnemonic(self) -> str:
        raise NotImplementedError

    @property
    def op_str(self) -> str:
        raise NotImplementedError

    def __str__(self):
        return f"{self.address:#x}:\t{self.mnemonic}\t{self.op_str}"

    def __repr__(self):
        return f'<DisassemblerInsn "{self.mnemonic}" for {self.address:#x}>'


class CapstoneBlock(DisassemblerBlock):
    """
    Deep copy of the capstone blocks, which have serious issues with having extended lifespans
    outside of capstone itself
    """

    __slots__ = ()


class CapstoneInsn(DisassemblerInsn):
    """
    Represents a capstone instruction.
    """

    __slots__ = ("insn",)

    def __init__(self, capstone_insn):
        self.insn = capstone_insn

    @property
    def size(self) -> int:
        return self.insn.size

    @property
    def address(self) -> int:
        return self.insn.address

    @property
    def mnemonic(self) -> str:
        return self.insn.mnemonic

    @property
    def op_str(self) -> str:
        return self.insn.op_str

    def __getattr__(self, item):
        if item in ("__str__", "__repr__"):
            return self.__getattribute__(item)
        if hasattr(self.insn, item):
            return getattr(self.insn, item)
        raise AttributeError


class Block(Serializable):
    """
    Represents a basic block in a binary or a program.
    """

    BLOCK_MAX_SIZE = 4096

    # __slots__ = [
    #     "_backup_state",
    #     "_bytes",
    #     "_capstone",
    #     "_collect_data_refs",
    #     "_const_prop",
    #     "_cross_insn_opt",
    #     "_disassembly",
    #     "_extra_stop_points",
    #     "_initial_regs",
    #     "_instruction_addrs",
    #     "_instructions",
    #     "_load_from_ro_regions",
    #     "_max_size",
    #     "_opt_level",
    #     "_project",
    #     "_strict_block_end",
    #     "_traceflags",
    #     "_vex",
    #     "_vex_nostmt",
    #     "addr",
    #     "arch",
    #     "size",
    #     "thumb",
    # ]

    def __init__(
        self,
        addr,
        size,
        byte_string,
        project=None,
        arch: Arch | None = None,
        max_size=None,
        thumb=False,
        backup_state=None,
        extra_stop_points=None,
        opt_level=None,
        num_inst=None,
        traceflags=0,
        strict_block_end=None,
        collect_data_refs=False,
        cross_insn_opt=True,
        load_from_ro_regions=False,
        const_prop=False,
        initial_regs=None,
        skip_stmts=False,
        block_source=None,
    ):
        self.addr = addr
        self.size = size
        self._bytes = byte_string
        self._ir = None
        self._project = project
        self._arch = arch
        self._max_size = max_size
        self.thumb = thumb
        self._backup_state = backup_state
        self._extra_stop_points = extra_stop_points
        self._opt_level = opt_level
        self._num_inst = num_inst
        self._strict_block_end = strict_block_end
        self._collect_data_refs = collect_data_refs
        self._cross_insn_opt = cross_insn_opt
        self._load_from_ro_regions = load_from_ro_regions
        self._const_prop = const_prop
        self._initial_regs = initial_regs
        self._skip_stmts = skip_stmts
        self._block_source = block_source

    def __repr__(self):
        return f"<Block for {self.addr:#x}, {self.size} bytes>"

    def __getstate__(self):
        return {k: getattr(self, k) for k in self.__slots__ if k not in {"_capstone", "_disassembly", "_project"}}

    def __setstate__(self, data):
        for k, v in data.items():
            setattr(self, k, v)
        self._capstone = None
        self._disassembly = None
        self._project = None

    def __hash__(self):
        return hash((type(self), self.addr, self.bytes))

    def __eq__(self, other):
        return type(self) is type(other) and self.addr == other.addr and self.bytes == other.bytes

    def __ne__(self, other):
        return not self == other

    def ir(self):
        if self.addr and self.size > 0 and self._ir is None:
            l.warning("Not found IR at 0x%x with %d, should check.", self.addr, self.size)
        return self._ir

    def set_ir(self, ir):
        if self._ir is not None:
            l.warning("Please note that you are modifying the existing IR at %s", self)
        else:
            self._ir = ir

    @property
    def bytes(self) -> bytes | None:
        if self.addr and self.size > 0 and self._bytes is None:
            l.warning(f"The bytes at 0x%x should not be none.", self.addr)
        return self._bytes

    def get_block_source(self):
        return self._block_source