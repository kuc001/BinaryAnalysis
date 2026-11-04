"""Native lifting utilities shared by the two bounded byte inputs."""

from __future__ import annotations

import hashlib
import importlib.metadata
from pathlib import Path
import sys
from typing import Any, Callable, Iterable, TYPE_CHECKING

from .inputs import ELFImage, FunctionInput, InputBlock, InputError

if TYPE_CHECKING:
    from .vex_lowering import NativeChunk


def check_runtime() -> None:
    """Require the repository target environment and pinned native packages."""

    expected = Path(__file__).resolve().parents[2] / '.venv'
    if Path(sys.prefix).resolve() != expected.resolve():
        raise InputError('Use the explicit target .venv interpreter')
    for package in ('angr', 'pyvex', 'archinfo', 'cle', 'claripy'):
        if importlib.metadata.version(package) != '9.3.4':
            raise InputError('P4 frontend is pinned to ' + package + ' 9.3.4')


def native_arch(image: ELFImage) -> Any:
    """Create the archinfo architecture matching a validated ELF header.

    ``Any`` is restricted to this third-party boundary because archinfo exposes
    architecture-specific runtime classes without a common typed protocol.
    """

    import archinfo
    constructors = {3: archinfo.ArchX86, 62: archinfo.ArchAMD64, 40: archinfo.ArchARM,
                    8: archinfo.ArchMIPS32 if image.elf_class == 1 else archinfo.ArchMIPS64,
                    183: archinfo.ArchAArch64}
    if image.machine not in constructors:
        raise InputError('ELF machine has no validated frontend architecture mapping')
    return constructors[image.machine](endness='Iend_LE' if image.endian == 'little' else 'Iend_BE')


def collect_chunks(
    image: ELFImage,
    specifications: tuple[FunctionInput, ...],
    arch: Any,
    lift: Callable[[int, bytes, str], Any],
) -> list[NativeChunk]:
    """Lift selected blocks into bounded native chunks without skipping gaps.

    Decode failures become explicit failed chunks; they are not mistaken for
    successfully translated instructions. ``Any`` values are confined to the
    pyvex/archinfo call boundary.
    """

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


def discover_inputs(
    project: Any, addresses: Iterable[int] | None = None
) -> tuple[FunctionInput, ...]:
    """Discover explicitly selected function bounds through angr CFGFast.

    ``project`` is an angr runtime object and is intentionally typed only at the
    external-library boundary. Recovered extents are converted immediately to
    validated immutable frontend records.
    """

    wanted = tuple(addresses) if addresses is not None else (project.entry,)
    if not wanted or any(type(a) is not int for a in wanted):
        raise InputError('Explicit function addresses required')
    cfg = project.analyses.CFGFast(function_starts=list(wanted), force_complete_scan=False)
    records = []
    for address in wanted:
        function = cfg.kb.functions.get(address)
        if function is None:
            raise InputError('CFGFast did not recover selected function ' + hex(address))
        bounds = set()
        for block in function.blocks:
            if type(block.size) is int and block.size >= 0:
                mode = 'thumb' if getattr(block, 'thumb', False) else 'default'
                physical = block.addr & ~1 if mode == 'thumb' else block.addr
                candidate = InputBlock(
                    physical,
                    physical + block.size,
                    mode,
                    boundary=(block.size == 0),
                )
                bounds.add(candidate)
            else:
                raise InputError('CFG produced an invalid code extent')
        raw_blocks = tuple(bounds)
        partitioned = _partition_discovered_blocks(raw_blocks)
        physical = (
            address & ~1
            if project.arch.name.startswith('ARM') and address & 1
            else address
        )
        records.append(FunctionInput(
            physical,
            function.name,
            partitioned,
            _normalized_discovered_edges(function, raw_blocks, partitioned),
        ))
    return tuple(records)


def _partition_discovered_blocks(
    blocks: tuple[InputBlock, ...],
) -> tuple[InputBlock, ...]:
    """Partition CFGFast shared suffixes into non-overlapping input blocks.

    CFGFast may represent both a fall-through block and a branch target that
    starts inside it.  Both ranges are valid views of the same instruction
    bytes, but ``FunctionInput`` deliberately requires a byte partition.  All
    recovered starts and ends therefore become cut points.  An atomic interval
    is retained when at least one source block covers it.  Conflicting decode
    modes remain an error because byte partitioning cannot resolve them.
    """

    concrete = tuple(block for block in blocks if not block.boundary)
    cuts = sorted({
        value
        for block in concrete
        for value in (block.start, block.end)
    })
    result = []
    for start, end in zip(cuts, cuts[1:]):
        covering = tuple(
            block for block in concrete
            if block.start <= start and end <= block.end
        )
        if not covering:
            continue
        modes = {block.mode for block in covering}
        if len(modes) != 1:
            raise InputError(
                'CFG contains overlapping blocks with conflicting decode modes'
            )
        result.append(InputBlock(start, end, modes.pop()))
    for boundary in (block for block in blocks if block.boundary):
        if any(block.start == boundary.start for block in result):
            raise InputError(
                'CFG boundary conflicts with a recovered block start'
            )
        result.append(boundary)
    return tuple(sorted(result, key=lambda block: block.start))


def _normalized_discovered_edges(
    function: Any,
    original: tuple[InputBlock, ...],
    partitioned: tuple[InputBlock, ...],
) -> tuple[tuple[int, int], ...]:
    """Map CFGFast edges and shared-block fall-through to the partition."""

    concrete = tuple(block for block in original if not block.boundary)
    starts = {block.start for block in partitioned}
    edges = set()

    # A cut introduced inside one original block is not a new branch. Execution
    # falls through from the prefix into the shared suffix.
    for block in concrete:
        fragments = tuple(
            item for item in partitioned
            if block.start <= item.start and item.end <= block.end
        )
        edges.update(
            (left.start, right.start)
            for left, right in zip(fragments, fragments[1:])
        )

    def physical(node: Any) -> int:
        address = int(node.addr)
        return address & ~1 if getattr(node, 'thumb', False) else address

    for source, target, data in function.graph.edges(data=True):
        if data.get('outside', False):
            continue
        source_start = physical(source)
        target_start = physical(target)
        source_size = int(getattr(source, 'size', 0) or 0)
        candidates = tuple(
            item for item in partitioned
            if source_start <= item.start
            and item.end <= source_start + source_size
        )
        normalized_source = (
            candidates[-1].start if candidates else source_start
        )
        if normalized_source in starts and target_start in starts:
            edges.add((normalized_source, target_start))
    return tuple(sorted(edges))
