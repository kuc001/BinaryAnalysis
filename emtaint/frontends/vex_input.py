"""Native lifting utilities shared by the two bounded byte inputs."""
import hashlib
import importlib.metadata
from pathlib import Path
import sys

from .inputs import InputError, FunctionInput, InputBlock


def check_runtime():
    expected = Path(__file__).resolve().parents[2] / '.venv'
    if Path(sys.prefix).resolve() != expected.resolve():
        raise InputError('Use the explicit target .venv interpreter')
    for package in ('angr', 'pyvex', 'archinfo', 'cle', 'claripy'):
        if importlib.metadata.version(package) != '9.3.4':
            raise InputError('P4 frontend is pinned to ' + package + ' 9.3.4')


def native_arch(image):
    import archinfo
    constructors = {3: archinfo.ArchX86, 62: archinfo.ArchAMD64, 40: archinfo.ArchARM,
                    8: archinfo.ArchMIPS32 if image.elf_class == 1 else archinfo.ArchMIPS64,
                    183: archinfo.ArchAArch64}
    if image.machine not in constructors:
        raise InputError('ELF machine has no validated frontend architecture mapping')
    return constructors[image.machine](endness='Iend_LE' if image.endian == 'little' else 'Iend_BE')


def collect_chunks(image, specifications, arch, lift):
    import pyvex
    from .vex_lowering import NativeChunk
    if type(specifications) is not tuple or not specifications:
        raise InputError('Explicit immutable function selection required')
    if len({f.address for f in specifications}) != len(specifications):
        raise InputError('Duplicate selected function')
    chunks = []
    for function in specifications:
        if type(function) is not FunctionInput:
            raise InputError('Expected FunctionInput')
        for block in function.blocks:
            if block.boundary:
                chunks.append(NativeChunk(function, block.start, block.end, block.start, block.end,
                    block.mode, None, hashlib.sha256(b'').hexdigest(), 'InputBoundary: IDA supplied no instructions'))
                continue
            if block.mode == 'thumb' and (not arch.name.startswith('ARM') or block.start & 1):
                raise InputError('Thumb input needs an ARM architecture and an even physical address')
            if block.mode == 'arm' and not arch.name.startswith('ARM'):
                raise InputError('ARM mode on a different architecture')
            cursor = block.start
            while cursor < block.end:
                data = image.read(cursor, block.end - cursor)
                digest = hashlib.sha256(data).hexdigest()
                try:
                    vex = lift(cursor, data, block.mode)
                except pyvex.PyVEXError as error:
                    chunks.append(NativeChunk(function, block.start, block.end, cursor, block.end,
                        block.mode, None, digest, type(error).__name__ + ': ' + str(error)))
                    break
                if vex.size <= 0 or vex.size > len(data):
                    chunks.append(NativeChunk(function, block.start, block.end, cursor, block.end,
                        block.mode, None, digest, 'VEX made no bounded decoding progress'))
                    break
                end = cursor + vex.size
                chunks.append(NativeChunk(function, block.start, block.end, cursor, end, block.mode, vex,
                                           hashlib.sha256(data[:vex.size]).hexdigest()))
                cursor = end
                if vex.jumpkind == 'Ijk_NoDecode' and cursor < block.end:
                    chunks.append(NativeChunk(function, block.start, block.end, cursor, block.end,
                        block.mode, None, hashlib.sha256(image.read(cursor, block.end - cursor)).hexdigest(),
                        'Undecoded tail after Ijk_NoDecode'))
                    break
    return chunks


def discover_inputs(project, addresses=None):
    wanted = tuple(addresses) if addresses is not None else (project.entry,)
    if not wanted or any(type(a) is not int for a in wanted):
        raise InputError('Explicit function addresses required')
    cfg = project.analyses.CFGFast(function_starts=list(wanted), force_complete_scan=False)
    records = []
    for address in wanted:
        function = cfg.kb.functions.get(address)
        if function is None:
            raise InputError('CFGFast did not recover selected function ' + hex(address))
        bounds = {}
        for block in function.blocks:
            if type(block.size) is int and block.size >= 0:
                mode = 'thumb' if getattr(block, 'thumb', False) else 'default'
                physical = block.addr & ~1 if mode == 'thumb' else block.addr
                prior = bounds.get(physical)
                candidate = InputBlock(physical, physical + block.size, mode, boundary=(block.size == 0))
                if prior is not None and prior != candidate:
                    raise InputError('CFG contains ambiguous overlapping block variants')
                bounds[physical] = candidate
            else:
                raise InputError('CFG produced an invalid code extent')
        physical = address & ~1 if project.arch.name.startswith('ARM') and address & 1 else address
        records.append(FunctionInput(physical, function.name, tuple(sorted(bounds.values(), key=lambda b: b.start))))
    return tuple(records)
