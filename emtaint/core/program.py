"""P2 immutable program metadata. No native IR, access paths, or heap semantics."""
from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType

from .identity import (BinaryId, FunctionId, BlockId, ProgramPoint, CallSiteId,
                       MemoryObjectId, integer, text, typed, tuple_of)


class Completeness(str, Enum):
    """Whether a model covers its declared analysis scope."""

    COMPLETE = 'complete'
    INCOMPLETE = 'incomplete'
    UNKNOWN = 'unknown'


class Endian(str, Enum):
    """Byte order used for architecture memory operations."""

    LITTLE = 'little'
    BIG = 'big'


@dataclass(frozen=True)
class Register:
    """Architecture register name, width, and optional native offset."""

    name: str
    bits: int
    offset: int | None = None

    def __post_init__(self):
        text(self.name, 'register name')
        integer(self.bits, 'register bits', 1)
        if self.offset is not None:
            integer(self.offset, 'register offset')


@dataclass(frozen=True)
class Architecture:
    """Validated address, pointer, byte, endian, and register description."""

    name: str
    address_bits: int
    pointer_bits: int
    endian: Endian
    byte_bits: int = 8
    registers: tuple[Register, ...] = ()

    def __post_init__(self):
        text(self.name, 'architecture name')
        integer(self.address_bits, 'address bits', 1)
        integer(self.pointer_bits, 'pointer bits', 1)
        integer(self.byte_bits, 'byte bits', 1)
        if self.address_bits > 4096 or self.pointer_bits > self.address_bits:
            raise ValueError('Unsupported architecture widths')
        typed(self.endian, Endian, 'endianness')
        tuple_of(self.registers, Register, 'registers')
        if len({r.name for r in self.registers}) != len(self.registers):
            raise ValueError('Duplicate register name')


@dataclass(frozen=True)
class ABI:
    """Calling-convention registers, stack properties, and save policy."""

    name: str
    argument_registers: tuple[str, ...] = ()
    return_registers: tuple[str, ...] = ()
    stack_pointer: str | None = None
    stack_alignment: int | None = None
    caller_saved: tuple[str, ...] = ()
    callee_saved: tuple[str, ...] = ()

    def __post_init__(self):
        text(self.name, 'ABI name')
        for names in (self.argument_registers, self.return_registers, self.caller_saved, self.callee_saved):
            tuple_of(names, str, 'ABI registers')
            if len(set(names)) != len(names):
                raise ValueError('Duplicate ABI register')
            for name in names:
                text(name, 'ABI register')
        if self.stack_pointer is not None:
            text(self.stack_pointer, 'stack pointer')
        if self.stack_alignment is not None:
            integer(self.stack_alignment, 'stack alignment', 1)
            if self.stack_alignment & (self.stack_alignment - 1):
                raise ValueError('Stack alignment must be a power of two')


@dataclass(frozen=True)
class BasicBlock:
    """Non-empty block extent identified by an image-relative block ID."""

    id: BlockId
    size: int

    def __post_init__(self):
        typed(self.id, BlockId, 'block ID')
        integer(self.size, 'block size', 1)


@dataclass(frozen=True)
class Function:
    """Immutable function metadata and its validated block membership."""

    id: FunctionId
    name: str
    blocks: tuple[BasicBlock, ...] = ()
    entry: BlockId | None = None
    returning: bool | None = None
    is_syscall: bool | None = None
    is_simprocedure: bool | None = None

    def __post_init__(self):
        typed(self.id, FunctionId, 'function ID')
        text(self.name, 'function name', allow_empty=True)
        tuple_of(self.blocks, BasicBlock, 'function blocks')
        if self.returning is not None and type(self.returning) is not bool:
            raise TypeError('Returning must be boolean or unknown')
        if any(flag is not None and type(flag) is not bool for flag in (self.is_syscall, self.is_simprocedure)):
            raise TypeError('Function flags must be booleans or unknown')
        ids = {b.id for b in self.blocks}
        if len(ids) != len(self.blocks) or any(b.function != self.id for b in ids):
            raise ValueError('Duplicate or foreign block in function')
        if self.entry is not None and self.entry not in ids:
            raise ValueError('Entry is not a block of this function')


class CallKind(str, Enum):
    """Origin classification for a declared call site."""

    DIRECT = 'direct'
    INDIRECT = 'indirect'
    EXTERNAL = 'external'
    SYSCALL = 'syscall'
    UNKNOWN = 'unknown'


@dataclass(frozen=True)
class CallSite:
    """Call occurrence and its direct, indirect, external, or unknown kind."""

    id: CallSiteId
    kind: CallKind = CallKind.UNKNOWN

    def __post_init__(self):
        typed(self.id, CallSiteId, 'callsite ID')
        typed(self.kind, CallKind, 'call kind')


@dataclass(frozen=True)
class MemoryObject:
    """Identity/provenance descriptor, not an AbstractHeap cell or MemoryVersion."""
    id: MemoryObjectId
    provenance: str
    size_bytes: int | None = None
    address_space: str = 'default'

    def __post_init__(self):
        typed(self.id, MemoryObjectId, 'memory object ID')
        text(self.provenance, 'object provenance')
        text(self.address_space, 'address space')
        if self.size_bytes is not None:
            integer(self.size_bytes, 'object size')


@dataclass(frozen=True)
class Program:
    """One image and load mapping; native frontend coverage is never assumed."""
    binary: BinaryId
    architecture: Architecture
    abi: ABI
    functions: tuple[Function, ...] = ()
    callsites: tuple[CallSite, ...] = ()
    image_base: int = 0
    status: Completeness = Completeness.UNKNOWN
    diagnostics: tuple[str, ...] = ('Frontend coverage not established',)
    _functions: object = field(init=False, repr=False, compare=False)
    _blocks: object = field(init=False, repr=False, compare=False)
    _callsites: object = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        typed(self.binary, BinaryId, 'program binary')
        typed(self.architecture, Architecture, 'architecture')
        typed(self.abi, ABI, 'ABI')
        typed(self.status, Completeness, 'program completeness')
        tuple_of(self.functions, Function, 'program functions')
        tuple_of(self.callsites, CallSite, 'program callsites')
        tuple_of(self.diagnostics, str, 'program diagnostics')
        self.absolute_address(0)
        names = {r.name for r in self.architecture.registers}
        used = set(self.abi.argument_registers + self.abi.return_registers + self.abi.caller_saved + self.abi.callee_saved)
        if self.abi.stack_pointer is not None:
            used.add(self.abi.stack_pointer)
        if not used <= names:
            raise ValueError('ABI refers to undeclared registers')
        functions, blocks = {}, {}
        for function in self.functions:
            if function.id.binary != self.binary or function.id in functions:
                raise ValueError('Duplicate or foreign function')
            self.absolute_address(function.id.rva)
            functions[function.id] = function
            for block in function.blocks:
                self.absolute_address(block.id.rva + block.size - 1)
                blocks[block.id] = block
        object.__setattr__(self, '_functions', MappingProxyType(functions))
        object.__setattr__(self, '_blocks', MappingProxyType(blocks))
        sites = {}
        for site in self.callsites:
            self.validate_point(site.id.point)
            if site.id in sites:
                raise ValueError('Duplicate callsite')
            sites[site.id] = site
        object.__setattr__(self, '_callsites', MappingProxyType(sites))

    def absolute_address(self, rva: int) -> int:
        """Translate an RVA to an absolute address within architecture width."""

        integer(self.image_base, 'image base')
        integer(rva, 'RVA')
        address = self.image_base + rva
        if address >= (1 << self.architecture.address_bits):
            raise ValueError('Address is outside architecture width')
        return address

    def relative_address(self, address: int) -> int:
        """Translate an absolute mapped address to an image-relative address."""

        integer(address, 'absolute address')
        rva = address - self.image_base
        if rva < 0 or self.absolute_address(rva) != address:
            raise ValueError('Address precedes image base')
        return rva

    def function(self, identity: FunctionId) -> Function:
        """Return a registered function or propagate ``KeyError``."""

        return self._functions[identity]

    def function_at(self, address: int) -> Function | None:
        """Return the function whose entry equals an absolute address."""

        return self._functions.get(FunctionId(self.binary, self.relative_address(address)))

    def block(self, identity: BlockId) -> BasicBlock:
        """Return a registered basic block or propagate ``KeyError``."""

        return self._blocks[identity]

    def callsite(self, identity: CallSiteId) -> CallSite:
        """Return a registered call site or propagate ``KeyError``."""

        return self._callsites[identity]

    def validate_point(self, point: ProgramPoint) -> None:
        """Validate block registration and optional instruction RVA bounds."""

        typed(point, ProgramPoint, 'program point')
        if point.block not in self._blocks:
            raise ValueError('Point refers to an unregistered block')
        block = self._blocks[point.block]
        if point.instruction_rva is not None and not block.id.rva <= point.instruction_rva < block.id.rva + block.size:
            raise ValueError('Instruction is outside its block')
