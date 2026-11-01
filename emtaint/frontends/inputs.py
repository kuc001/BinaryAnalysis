"""Read-only bounded input descriptions and ELF byte mapping (no native imports)."""
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import struct


class InputError(ValueError):
    pass


def address(value):
    if type(value) is not int or value < 0 or value >= 1 << 64:
        raise InputError('Expected an unsigned address')
    return value


@dataclass(frozen=True)
class InputBlock:
    start: int
    end: int
    mode: str = 'default'
    boundary: bool = False

    def __post_init__(self):
        address(self.start)
        address(self.end)
        if (type(self.boundary) is not bool or self.end < self.start
                or (self.end == self.start) != self.boundary or self.mode not in ('default', 'arm', 'thumb')):
            raise InputError('Invalid block bounds or instruction mode')


@dataclass(frozen=True)
class CallHint:
    block: int
    instruction: int
    target: int | str

    def __post_init__(self):
        address(self.block)
        address(self.instruction)
        if type(self.target) is int:
            address(self.target)
        elif type(self.target) is not str or not self.target:
            raise InputError('Call target must be an address or nonempty provenance name')


@dataclass(frozen=True)
class FunctionInput:
    address: int
    name: str
    blocks: tuple[InputBlock, ...]
    edges: tuple[tuple[int, int], ...] = ()
    calls: tuple[CallHint, ...] = ()

    def __post_init__(self):
        address(self.address)
        if type(self.name) is not str or type(self.blocks) is not tuple or not self.blocks:
            raise InputError('Function needs explicit immutable block bounds and name')
        if any(type(b) is not InputBlock for b in self.blocks):
            raise InputError('Invalid block descriptor')
        starts = {b.start for b in self.blocks}
        if len(starts) != len(self.blocks) or self.address not in starts:
            raise InputError('Duplicate blocks or missing function entry')
        ordered = sorted(self.blocks, key=lambda b: b.start)
        if any(a.end > b.start for a, b in zip(ordered, ordered[1:])):
            raise InputError('Overlapping source blocks require an explicit future input model')
        if type(self.edges) is not tuple or any(type(e) is not tuple or len(e) != 2
                or any(type(v) is not int or v not in starts for v in e) for e in self.edges):
            raise InputError('Dangling IDA CFG edge')
        if type(self.calls) is not tuple:
            raise InputError('Call hints must be immutable')
        for call in self.calls:
            if type(call) is not CallHint or call.block not in starts:
                raise InputError('Callsite refers to an unknown block')
            block = next(b for b in self.blocks if b.start == call.block)
            address(call.instruction)
            if not block.start <= call.instruction < block.end or type(call.target) not in (str, int):
                raise InputError('Invalid callsite bounds/target')
            if type(call.target) is int:
                address(call.target)


def parse_ida_cfg(document, *, mode='default'):
    if type(document) is not dict or not document:
        raise InputError('IDA CFG must be a nonempty function-address mapping')
    result = []
    for name, payload in document.items():
        try:
            if type(name) is not str or type(payload) is not dict:
                raise InputError('Invalid IDA function entry')
            start = int(name, 16)
            if not {'block', 'jmp', 'call'} <= payload.keys():
                raise InputError('Missing block/jmp/call metadata')
            if not payload.keys() <= {'block', 'jmp', 'call', 'name'}:
                raise InputError('Unrecognized IDA metadata fields require an explicit adapter')
            if any(type(payload[k]) is not list for k in ('block', 'jmp', 'call')):
                raise InputError('IDA tables must be JSON arrays')
            if any(type(row) is not list or len(row) != 2 for row in payload['block']):
                raise InputError('Block row must contain start/end')
            blocks = tuple(InputBlock(*row, mode=mode, boundary=(row[0] == row[1])) for row in payload['block'])
            edges = tuple(tuple(address(v) for v in row) for row in payload['jmp'])
            calls = tuple(CallHint(*row) for row in payload['call'])
            result.append(FunctionInput(start, payload.get('name', name), blocks, edges, calls))
        except (ValueError, TypeError) as error:
            raise InputError('Malformed IDA function ' + str(name) + ': ' + str(error)) from error
    if len({f.address for f in result}) != len(result):
        raise InputError('Duplicate normalized function address')
    return tuple(sorted(result, key=lambda f: f.address))


def read_ida_cfg(path, *, mode='default'):
    def pairs(items):
        values = {}
        for key, value in items:
            if key in values:
                raise InputError('Duplicate IDA JSON key')
            values[key] = value
        return values
    return parse_ida_cfg(json.loads(Path(path).read_text(encoding='utf-8-sig'), object_pairs_hook=pairs), mode=mode)


class ELFImage:
    """ELF ET_EXEC link-time virtual addresses; no guessed PIE relocation base."""
    def __init__(self, data):
        if type(data) is not bytes or data[:4] != b'\x7fELF' or len(data) < 52:
            raise InputError('Invalid ELF bytes')
        self.data = data
        self.sha256 = hashlib.sha256(data).hexdigest()
        self.elf_class, self.encoding = data[4], data[5]
        if self.elf_class not in (1, 2) or self.encoding not in (1, 2):
            raise InputError('Unsupported ELF class/encoding')
        order = '<' if self.encoding == 1 else '>'
        self.endian = 'little' if self.encoding == 1 else 'big'
        try:
            self.elf_type, self.machine = struct.unpack_from(order + 'HH', data, 16)
            if self.elf_type != 2:
                raise InputError('Only ET_EXEC is mapped by this frontend; PIE needs explicit relocation support')
            if self.elf_class == 1:
                phoff = struct.unpack_from(order + 'I', data, 28)[0]
                entsize, count = struct.unpack_from(order + 'HH', data, 42)
                fmt = order + 'IIIIIIII'
            else:
                phoff = struct.unpack_from(order + 'Q', data, 32)[0]
                entsize, count = struct.unpack_from(order + 'HH', data, 54)
                fmt = order + 'IIQQQQQQ'
            if entsize < struct.calcsize(fmt) or count == 0 or phoff + count * entsize > len(data):
                raise InputError('Invalid ELF program-header bounds')
            self.segments = []
            for i in range(count):
                row = struct.unpack_from(fmt, data, phoff + i * entsize)
                if self.elf_class == 1:
                    kind, offset, vaddr, _, filesz, memsz, flags, _ = row
                else:
                    kind, flags, offset, vaddr, _, filesz, memsz, _ = row
                if kind == 1:
                    if filesz > memsz or offset + filesz > len(data):
                        raise InputError('Invalid ELF segment file range')
                    self.segments.append((vaddr, offset, filesz, memsz, flags))
        except struct.error as error:
            raise InputError('Truncated ELF structure') from error
        if not self.segments:
            raise InputError('ELF has no loadable segments')
        self.image_base = min(s[0] for s in self.segments)

    @classmethod
    def from_path(cls, path):
        return cls(Path(path).read_bytes())

    def read(self, start, size):
        address(start)
        if type(size) is not int or size <= 0:
            raise InputError('Read size must be positive')
        for vaddr, offset, filesz, _, flags in self.segments:
            if vaddr <= start and start + size <= vaddr + filesz and flags & 1:
                pos = offset + start - vaddr
                return self.data[pos:pos + size]
        raise InputError('Code bytes outside a file-backed executable ELF segment')
