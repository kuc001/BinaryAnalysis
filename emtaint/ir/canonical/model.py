"""Typed non-SSA CIR effects, kept separate from the legacy VEX class hierarchy."""
from collections.abc import Iterator
from dataclasses import dataclass, fields
from enum import Enum

from emtaint.core import (ABI, Architecture, BinaryId, BlockId, CallSiteId, Completeness,
                           Endian, FunctionId, Program)
from emtaint.core.contracts import (Record, Assessment, Origin, Producer, ValueType,
    TypeKind, ValueRef, Constant, Operand, bits, boolean, key, CIR_VERSION, MEMORY_VERSION, validate_value_operation)
from emtaint.core.identity import integer, text
from emtaint.memory.state import MemorySnapshot


class ValueOp(str, Enum):
    """Canonical scalar operations with explicit signedness and width behavior."""

    COPY = 'copy'
    ADD = 'add'
    SUB = 'sub'
    MUL = 'mul'
    AND = 'and_bits'
    OR = 'or_bits'
    XOR = 'xor_bits'
    EQ = 'eq'
    ULT = 'ult'
    SLT = 'slt'
    NOT = 'not'
    EXTRACT = 'extract'
    ZERO_EXTEND = 'zero_extend'
    SIGN_EXTEND = 'sign_extend'
    CONCAT = 'concat'
    IF = 'if'


@dataclass(frozen=True)
class Compute(Record):
    """Compute one typed CIR value without mutating architectural state."""

    origin: str
    result: ValueRef
    op: ValueOp
    args: tuple[Operand, ...]
    params: tuple[int, ...] = ()

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        validate_value_operation(self.op.value, self.result.type, [arg.type for arg in self.args], self.params)


def memory_access(
    address: Operand,
    width: int,
    endian: Endian,
    guard: Operand,
    address_space: str,
    alignment: int | None,
) -> None:
    """Validate shared load/store width, guard, space, and alignment contracts."""

    if address.type.kind != TypeKind.POINTER or address.type.address_space != address_space:
        raise ValueError('Memory address needs a matching pointer address space')
    bits(width, byte_access=True)
    boolean(guard)
    if alignment is not None:
        integer(alignment, 'memory alignment', 1)
        if alignment & (alignment - 1):
            raise ValueError('Alignment must be a power of two')


@dataclass(frozen=True)
class LoadEffect(Record):
    """Read an explicitly sized and ordered memory value when ``guard`` is true."""

    origin: str
    result: ValueRef
    address: Operand
    width_bits: int
    endian: Endian
    guard: Operand
    address_space: str = 'default'
    alignment_bytes: int | None = None
    volatile: bool = False

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        memory_access(self.address, self.width_bits, self.endian, self.guard, self.address_space, self.alignment_bytes)
        if self.result.type.bits != self.width_bits or self.result.type.kind == TypeKind.BOOL:
            raise ValueError('Load result width/sort mismatch')


@dataclass(frozen=True)
class StoreEffect(Record):
    """Write an explicitly sized and ordered memory value when ``guard`` is true."""

    origin: str
    address: Operand
    value: Operand
    width_bits: int
    endian: Endian
    guard: Operand
    address_space: str = 'default'
    alignment_bytes: int | None = None
    volatile: bool = False

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        memory_access(self.address, self.width_bits, self.endian, self.guard, self.address_space, self.alignment_bytes)
        if self.value.type.bits != self.width_bits or self.value.type.kind == TypeKind.BOOL:
            raise ValueError('Store value width/sort mismatch')


@dataclass(frozen=True)
class RegisterSlice(Record):
    """Identify a bounded bit slice within one architectural register."""

    register: str
    bit_offset: int
    width_bits: int
    register_width_bits: int

    def __post_init__(self):
        super().__post_init__()
        text(self.register, 'register')
        integer(self.bit_offset, 'register bit offset')
        bits(self.width_bits)
        bits(self.register_width_bits)
        if self.bit_offset + self.width_bits > self.register_width_bits:
            raise ValueError('Register slice exceeds its declared register')


class RegisterWritePolicy(str, Enum):
    """Describe how a slice write affects bits outside the written slice."""

    FULL = 'full'
    PRESERVE_OTHERS = 'preserve_others'
    ZERO_UPPER = 'zero_upper'


@dataclass(frozen=True)
class ReadRegister(Record):
    """Read a declared register slice into a width-matched CIR value."""

    origin: str
    result: ValueRef
    source: RegisterSlice

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        if self.result.type.bits != self.source.width_bits or self.result.type.kind == TypeKind.BOOL:
            raise ValueError('Register read width/sort mismatch')


@dataclass(frozen=True)
class WriteRegister(Record):
    """Conditionally update a register slice under an explicit write policy."""

    origin: str
    target: RegisterSlice
    value: Operand
    policy: RegisterWritePolicy
    guard: Operand

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        boolean(self.guard)
        if self.value.type.bits != self.target.width_bits or self.value.type.kind == TypeKind.BOOL:
            raise ValueError('Register write width/sort mismatch')
        if self.policy == RegisterWritePolicy.FULL and (self.target.bit_offset != 0 or self.target.width_bits != self.target.register_width_bits):
            raise ValueError('Full register write requires a whole register')
        if self.policy == RegisterWritePolicy.ZERO_UPPER and self.target.bit_offset != 0:
            raise ValueError('Zero-upper write must start at the low bit')


@dataclass(frozen=True)
class DirectTarget(Record):
    """Name a statically proven internal call target."""

    function: FunctionId


@dataclass(frozen=True)
class IndirectTarget(Record):
    """Represent a runtime call target computed as a pointer value."""

    address: Operand

    def __post_init__(self):
        super().__post_init__()
        if self.address.type.kind != TypeKind.POINTER:
            raise ValueError('Indirect call target must be a pointer')


@dataclass(frozen=True)
class ExternalTarget(Record):
    """Name a proven external symbol target."""

    symbol: str

    def __post_init__(self):
        super().__post_init__()
        text(self.symbol, 'external symbol')


@dataclass(frozen=True)
class UnknownTarget(Record):
    """Retain the reason a call target could not be classified."""

    reason: str

    def __post_init__(self):
        super().__post_init__()
        text(self.reason, 'unknown call target reason')


@dataclass(frozen=True)
class CallFootprint(Record):
    """Conservatively describe memory and register effects of a call."""

    read_regions: tuple[str, ...] = ('*',)
    write_regions: tuple[str, ...] = ('*',)
    clobbered_registers: tuple[str, ...] = ('*',)
    unknown: bool = True
    reason: str = 'External side effects have not been modeled'

    def __post_init__(self):
        super().__post_init__()
        text(self.reason, 'call footprint evidence/reason')
        if any(not name for name in self.read_regions + self.write_regions + self.clobbered_registers):
            raise ValueError('Footprint names must be nonempty')
        if self.unknown and (self.write_regions != ('*',) or self.clobbered_registers != ('*',)):
            raise ValueError('Unknown external effects must conservatively include all writes/clobbers')


@dataclass(frozen=True)
class CallEffect(Record):
    """Model a guarded call, its ABI, results, and conservative footprint."""

    origin: str
    site: CallSiteId
    target: DirectTarget | IndirectTarget | ExternalTarget | UnknownTarget
    arguments: tuple[Operand, ...]
    results: tuple[ValueRef, ...]
    abi: ABI
    guard: Operand
    footprint: CallFootprint = CallFootprint()

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        boolean(self.guard)


@dataclass(frozen=True)
class BranchEffect(Record):
    """Terminate a block with a boolean choice between two declared blocks."""

    origin: str
    condition: Operand
    if_true: BlockId
    if_false: BlockId

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        boolean(self.condition)


@dataclass(frozen=True)
class JumpEffect(Record):
    """Terminate a block with a declared block or computed pointer target."""

    origin: str
    target: BlockId | Operand

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        if not isinstance(self.target, BlockId) and self.target.type.kind != TypeKind.POINTER:
            raise ValueError('Computed jump requires a pointer')


@dataclass(frozen=True)
class ReturnEffect(Record):
    """Return typed values from a function when the guard is true."""

    origin: str
    values: tuple[Operand, ...]
    guard: Operand

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        boolean(self.guard)


@dataclass(frozen=True)
class HavocEffect(Record):
    """Explicitly invalidate named state when exact effects are unavailable."""

    origin: str
    regions: tuple[str, ...]
    registers: tuple[str, ...]
    guard: Operand
    reason: str

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        boolean(self.guard)
        text(self.reason, 'havoc reason')
        if not (self.regions or self.registers) or any(not n for n in self.regions + self.registers):
            raise ValueError('Havoc must identify potentially affected state')


@dataclass(frozen=True)
class UnknownEffect(Record):
    """Preserve an unsupported source effect as a conservative state change."""

    origin: str
    source_opcode: str
    reason: str
    may_write_regions: tuple[str, ...] = ('*',)
    may_write_registers: tuple[str, ...] = ('*',)
    may_change_control: bool = True

    def __post_init__(self):
        super().__post_init__()
        key(self.origin)
        text(self.source_opcode, 'unknown opcode')
        text(self.reason, 'unknown effect reason')
        if not (self.may_write_regions or self.may_write_registers or self.may_change_control):
            raise ValueError('Unknown effect cannot silently become a no-op')
        if any(not name for name in self.may_write_regions + self.may_write_registers):
            raise ValueError('Unknown effect footprints need nonempty names')


Effect = (Compute | LoadEffect | StoreEffect | ReadRegister | WriteRegister | CallEffect
          | BranchEffect | JumpEffect | ReturnEffect | HavocEffect | UnknownEffect)


@dataclass(frozen=True)
class CIRBlock(Record):
    """Hold ordered effects for one canonical block and its optional byte extent."""

    id: BlockId
    effects: tuple[Effect, ...]
    size_bytes: int | None = None

    def __post_init__(self):
        super().__post_init__()
        if self.size_bytes is not None:
            integer(self.size_bytes, 'block size', 1)
        terminators = (BranchEffect, JumpEffect, ReturnEffect)
        if any(isinstance(effect, terminators) for effect in self.effects[:-1]):
            raise ValueError('Control terminator must be the last effect in a block')


def operands(record: object) -> Iterator[ValueRef | Constant]:
    """Inspect only declared CIR fields; no arbitrary frontend object traversal."""
    if isinstance(record, (ValueRef, Constant)):
        yield record
    elif isinstance(record, tuple):
        for item in record:
            yield from operands(item)
    elif isinstance(record, Record):
        for field in fields(record):
            yield from operands(getattr(record, field.name))


@dataclass(frozen=True)
class CIRFunction(Record):
    """Contain a closed, typed block/value graph for one binary function."""

    function_id: FunctionId
    values: tuple[ValueRef, ...]
    blocks: tuple[CIRBlock, ...]
    entry: BlockId | None
    abi: ABI

    def __post_init__(self):
        super().__post_init__()
        values = {value.id: value.type for value in self.values}
        blocks = {block.id for block in self.blocks}
        if len(values) != len(self.values) or len(blocks) != len(self.blocks):
            raise ValueError('Duplicate function value/block ID')
        if any(block.function != self.function_id for block in blocks) or (self.entry is not None and self.entry not in blocks):
            raise ValueError('Foreign block or dangling entry')
        for block in self.blocks:
            for effect in block.effects:
                for value in operands(effect):
                    if isinstance(value, ValueRef) and values.get(value.id) != value.type:
                        raise ValueError('Undeclared or inconsistently typed CIR value')
                targets = ((effect.if_true, effect.if_false) if isinstance(effect, BranchEffect)
                           else (effect.target,) if isinstance(effect, JumpEffect) and isinstance(effect.target, BlockId) else ())
                if any(target not in blocks for target in targets):
                    raise ValueError('Dangling branch target')
                if isinstance(effect, CallEffect) and effect.site.point.block != block.id:
                    raise ValueError('Callsite belongs to another block')


CAPABILITIES = frozenset(('typed-effects', 'memory-descriptors', 'access-graph-descriptors', 'taint-fact-descriptors'))


@dataclass(frozen=True)
class CIRModule(Record):
    """Bind canonical functions and memory facts to one architecture and binary.

    Construction validates address widths, byte endianness, provenance,
    capabilities, branch targets, register slices, and conservative unsupported
    effects. These checks are part of the persistent CIR wire contract.
    """

    producer: Producer
    architecture: Architecture
    endian: Endian
    binary_sha256: str
    functions: tuple[CIRFunction, ...]
    origin_map: tuple[Origin, ...]
    capabilities: tuple[str, ...]
    assessment: Assessment
    memory_snapshots: tuple[MemorySnapshot, ...] = ()
    schema_version: str = CIR_VERSION
    memory_semantics_version: str = MEMORY_VERSION

    def __post_init__(self):
        super().__post_init__()
        binary = BinaryId(self.binary_sha256)
        if (self.schema_version, self.memory_semantics_version) != (CIR_VERSION, MEMORY_VERSION):
            raise ValueError('Unsupported CIR / memory schema version')
        if self.endian != self.architecture.endian or self.architecture.byte_bits != 8:
            raise ValueError('Module endian / octet architecture mismatch')
        if not set(self.capabilities) <= CAPABILITIES or len(set(self.capabilities)) != len(self.capabilities):
            raise ValueError('Unknown or duplicate capability')
        fids = {f.function_id for f in self.functions}
        if len(fids) != len(self.functions) or any(fid.binary != binary for fid in fids):
            raise ValueError('Duplicate / foreign function in CIR')
        origins = {origin.id: origin for origin in self.origin_map}
        if len(origins) != len(self.origin_map) or any(o.point.function not in fids for o in self.origin_map):
            raise ValueError('Duplicate or foreign origin')
        source_blocks = {block.id: block for function in self.functions for block in function.blocks}
        for origin in self.origin_map:
            if origin.point.block not in source_blocks:
                raise ValueError('Origin names an undeclared CIR block')
            block = source_blocks[origin.point.block]
            address = origin.point.instruction_rva
            if address is not None and (not block.id.rva <= address < 1 << self.architecture.address_bits
                    or (block.size_bytes is not None and address >= block.id.rva + block.size_bytes)):
                raise ValueError('Origin instruction is outside its source block/address range')
        registers = {r.name: r.bits for r in self.architecture.registers}
        unmodeled = set()
        required_capabilities = set()
        for function in self.functions:
            Program(binary, self.architecture, function.abi)
            if self.assessment.status == Completeness.COMPLETE and function.blocks and function.entry is None:
                raise ValueError('Complete function requires a declared entry')
            if function.function_id.rva >= 1 << self.architecture.address_bits:
                raise ValueError('Function RVA exceeds architecture address width')
            for value in function.values:
                if value.type.kind == TypeKind.POINTER and value.type.bits != self.architecture.pointer_bits:
                    raise ValueError('Declared pointer width differs from the architecture')
            for block in function.blocks:
                if block.id.rva >= 1 << self.architecture.address_bits:
                    raise ValueError('Block RVA exceeds architecture address width')
                if block.size_bytes is not None and block.id.rva + block.size_bytes > 1 << self.architecture.address_bits:
                    raise ValueError('CIR block exceeds architecture address width')
                for effect in block.effects:
                    required_capabilities.add('typed-effects')
                    if effect.origin not in origins or origins[effect.origin].point.block != block.id:
                        raise ValueError('Missing origin or wrong source block')
                    point = origins[effect.origin].point
                    if point.instruction_rva is not None and not block.id.rva <= point.instruction_rva < 1 << self.architecture.address_bits:
                        raise ValueError('Origin instruction RVA exceeds the declared block/address range')
                    if block.size_bytes is not None and point.instruction_rva is not None and not block.id.rva <= point.instruction_rva < block.id.rva + block.size_bytes:
                        raise ValueError('Origin instruction lies outside the block')
                    for value in operands(effect):
                        if value.type.kind == TypeKind.POINTER and value.type.bits != self.architecture.pointer_bits:
                            raise ValueError('Pointer width differs from module architecture')
                    if isinstance(effect, (ReadRegister, WriteRegister)):
                        sl = effect.source if isinstance(effect, ReadRegister) else effect.target
                        if registers.get(sl.register) != sl.register_width_bits:
                            raise ValueError('Register slice differs from the architecture')
                    if isinstance(effect, CallEffect):
                        Program(binary, self.architecture, effect.abi)
                        if effect.site.point != point:
                            raise ValueError('Callsite and source origin program points differ')
                        if any(name != '*' and name not in registers for name in effect.footprint.clobbered_registers):
                            raise ValueError('Call footprint names an undeclared register')
                        if effect.footprint.unknown:
                            unmodeled.add('CallMemoryEffects')
                    if isinstance(effect, UnknownEffect):
                        unmodeled.add(effect.source_opcode)
                    clobbers = (effect.registers if isinstance(effect, HavocEffect)
                                else effect.may_write_registers if isinstance(effect, UnknownEffect) else ())
                    if any(name != '*' and name not in registers for name in clobbers):
                        raise ValueError('Havoc/unknown footprint names an undeclared register')
        if unmodeled and (self.assessment.status != Completeness.INCOMPLETE or not unmodeled <= set(self.assessment.unsupported_ops)):
            raise ValueError('Unsupported effects must remain explicit in module assessment')
        if len({snapshot.scope for snapshot in self.memory_snapshots}) != len(self.memory_snapshots):
            raise ValueError('Duplicate memory analysis scope')
        for snapshot in self.memory_snapshots:
            required_capabilities.add('memory-descriptors')
            if snapshot.graphs:
                required_capabilities.add('access-graph-descriptors')
            if snapshot.taint_facts:
                required_capabilities.add('taint-fact-descriptors')
            if snapshot.scope.function not in fids or snapshot.architecture != self.architecture:
                raise ValueError('Memory snapshot belongs to a foreign function/architecture')
            if any(o.id not in origins or origins[o.id] != o for o in snapshot.origin_map):
                raise ValueError('Memory/CIR provenance differs')
            if self.assessment.status == Completeness.COMPLETE and snapshot.assessment.status != Completeness.COMPLETE:
                raise ValueError('Incomplete memory snapshot cannot yield a complete module')
        if not required_capabilities <= set(self.capabilities):
            raise ValueError('Packet omits required capability declarations')
