"""Immutable structural indexes for demand-driven CIR analysis.

The index contains facts that depend only on one function body and its CFG.
It deliberately does not query memory, allocate SSE nodes, consume an
analysis budget, or retain query-local recursion state.
"""

from bisect import bisect_left
from collections import defaultdict, deque
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Mapping

from emtaint.core import BlockId
from emtaint.ir.canonical import (
    CallEffect,
    Compute,
    LoadEffect,
    ReadRegister,
    StoreEffect,
    UnknownEffect,
    WriteRegister,
)


Definition = tuple[BlockId, int, object]
PositionMap = Mapping[BlockId, tuple[int, ...]]
RegisterPositionMap = Mapping[tuple[BlockId, str], tuple[int, ...]]


def _block_order(block: BlockId) -> tuple[int, int, str]:
    """Return a deterministic order without depending on set iteration."""

    return block.rva, block.index, block.mode


def _last_before(positions: tuple[int, ...], cutoff: int) -> int | None:
    """Return the last zero-based position strictly before ``cutoff``."""

    index = bisect_left(positions, cutoff) - 1
    return positions[index] if index >= 0 else None


@dataclass(frozen=True)
class FunctionDemandIndex:
    """Read-only definition and CFG index for one immutable CIR function."""

    blocks: Mapping[BlockId, object]
    entry: BlockId
    predecessors: Mapping[BlockId, tuple[BlockId, ...]]
    value_definitions: Mapping[str, Definition]
    register_events: RegisterPositionMap
    wildcard_register_events: PositionMap
    stores: PositionMap
    calls: PositionMap
    effect_count: int

    @classmethod
    def build(cls, function, cfg) -> "FunctionDemandIndex":
        """Index immutable body structure without creating analysis values."""

        blocks = {block.id: block for block in function.blocks}
        predecessors = {block: set() for block in blocks}
        for edge in cfg.edges:
            if edge.source in blocks and edge.target in blocks:
                predecessors[edge.target].add(edge.source)

        value_definitions: dict[str, Definition] = {}
        register_events: dict[tuple[BlockId, str], list[int]] = defaultdict(list)
        wildcard_events: dict[BlockId, list[int]] = defaultdict(list)
        stores: dict[BlockId, list[int]] = defaultdict(list)
        calls: dict[BlockId, list[int]] = defaultdict(list)
        effect_count = 0

        for block in function.blocks:
            for position, effect in enumerate(block.effects):
                effect_count += 1
                if isinstance(effect, (Compute, ReadRegister, LoadEffect)):
                    value_definitions[effect.result.id] = (
                        block.id,
                        position,
                        effect,
                    )
                if isinstance(effect, CallEffect):
                    calls[block.id].append(position)
                    for result in effect.results:
                        value_definitions[result.id] = (
                            block.id,
                            position,
                            effect,
                        )
                    clobbers = effect.footprint.clobbered_registers
                    if "*" in clobbers:
                        wildcard_events[block.id].append(position)
                    for name in clobbers:
                        if name != "*":
                            register_events[block.id, name].append(position)
                elif isinstance(effect, WriteRegister):
                    register_events[
                        block.id, effect.target.register
                    ].append(position)
                elif isinstance(effect, UnknownEffect):
                    writes = effect.may_write_registers
                    if "*" in writes:
                        wildcard_events[block.id].append(position)
                    for name in writes:
                        if name != "*":
                            register_events[block.id, name].append(position)
                if isinstance(effect, StoreEffect):
                    stores[block.id].append(position)

        def freeze_positions(source):
            return MappingProxyType(
                {key: tuple(values) for key, values in source.items()}
            )

        frozen_predecessors = MappingProxyType(
            {
                block: tuple(sorted(values, key=_block_order))
                for block, values in predecessors.items()
            }
        )
        return cls(
            MappingProxyType(blocks),
            function.entry,
            frozen_predecessors,
            MappingProxyType(value_definitions),
            freeze_positions(register_events),
            freeze_positions(wildcard_events),
            freeze_positions(stores),
            freeze_positions(calls),
            effect_count,
        )

    def definition_cutoff(
        self, block: BlockId, index: int, register: str
    ) -> int:
        """Return one past the latest write/clobber before ``index``."""

        exact = _last_before(
            self.register_events.get((block, register), ()), index
        )
        wildcard = _last_before(
            self.wildcard_register_events.get(block, ()), index
        )
        latest = max(
            (position for position in (exact, wildcard) if position is not None),
            default=None,
        )
        return 0 if latest is None else latest + 1

    def reaching(
        self,
        block: BlockId,
        index: int,
        register: str,
        *,
        on_visit: Callable[[], None] | None = None,
    ) -> tuple[frozenset[tuple[BlockId, int]], bool]:
        """Find reaching register events using the indexed CFG.

        ``on_visit`` lets an owning engine preserve its budget accounting
        without coupling this structural index to mutable analysis state.
        """

        pending = deque(((block, index),))
        seen: set[tuple[BlockId, int]] = set()
        definitions: set[tuple[BlockId, int]] = set()
        entry = False
        while pending:
            current, cutoff = pending.popleft()
            if (current, cutoff) in seen:
                continue
            seen.add((current, cutoff))
            if on_visit is not None:
                on_visit()
            definition = self.definition_cutoff(
                current, cutoff, register
            )
            if definition:
                definitions.add((current, definition))
                continue
            incoming = self.predecessors[current]
            if current == self.entry or not incoming:
                entry = True
            pending.extend(
                (predecessor, len(self.blocks[predecessor].effects))
                for predecessor in incoming
            )
        return frozenset(definitions), entry

