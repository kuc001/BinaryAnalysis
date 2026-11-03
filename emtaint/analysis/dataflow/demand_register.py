"""Bit-slice register definitions for the P7 demand adapter."""

from emtaint.core import BlockId
from emtaint.core.contracts import ValueType
from emtaint.ir.canonical import RegisterSlice, WriteRegister
from emtaint.memory import SymbolicOp


class RegisterSliceResolver:
    """Resolve exact register slices while preserving CFG alternatives."""

    def __init__(self, owner) -> None:
        self.owner = owner

    def exact_before(
        self,
        block: BlockId,
        index: int,
        source: RegisterSlice,
        depth: int,
        seen: frozenset = frozenset(),
    ) -> tuple:
        """Follow only full-coverage slice definitions before a cutoff."""

        demand = self.owner
        key = block, index, source
        if key in seen:
            return (
                demand.port.unknown(
                    ValueType.bv(source.width_bits),
                    demand.blocks[block].effects[0].origin,
                    "Cyclic partial register demand",
                ),
            )
        seen = seen | {key}
        definitions, entry = demand.reaching(block, index, source.register)
        if definitions:
            alternatives = []
            for defined_block, cutoff in sorted(
                definitions,
                key=lambda item: (
                    item[0].rva,
                    item[0].index,
                    item[0].mode,
                    item[1],
                ),
            ):
                alternatives.append(
                    self.exact_definition(
                        defined_block, cutoff, source, depth + 1, seen
                    )
                )
            if entry:
                alternatives.append(
                    self.full_fallback(block, index, source, depth + 1)
                )
            return demand.union(alternatives)
        return self.full_fallback(block, index, source, depth + 1)

    def exact_definition(
        self,
        block: BlockId,
        cutoff: int,
        source: RegisterSlice,
        depth: int,
        seen: frozenset,
    ) -> tuple:
        """Resolve one reaching definition or conservatively fall back."""

        demand = self.owner
        write = demand.blocks[block].effects[cutoff - 1]
        if isinstance(write, WriteRegister):
            target = write.target
            disjoint = (
                target.bit_offset + target.width_bits <= source.bit_offset
                or source.bit_offset + source.width_bits <= target.bit_offset
            )
            if disjoint:
                return self.exact_before(
                    block, cutoff - 1, source, depth + 1, seen
                )
            if target == source:
                guards = demand.value(write.guard, depth + 1)
                choices = {
                    demand.guard_concrete(guard) for guard in guards
                }
                written = (
                    demand.value(write.value, depth + 1)
                    if choices != {False}
                    else ()
                )
                if choices == {True}:
                    demand.rules.add("p7.exact-partial-register-slice")
                    return written
                previous = self.exact_before(
                    block, cutoff - 1, source, depth + 1, seen
                )
                demand.rules.add("p7.conditional-partial-register-slice")
                return demand.union((written, previous))
        return self.full_fallback(block, cutoff, source, depth + 1)

    def full_fallback(
        self,
        block: BlockId,
        index: int,
        source: RegisterSlice,
        depth: int,
    ) -> tuple:
        """Extract the requested slice from a conservative full value."""

        demand = self.owner
        full = demand.register(
            block,
            index,
            source.register,
            source.register_width_bits,
            depth + 1,
        )
        return tuple(
            demand.port.operation(
                SymbolicOp.EXTRACT,
                ValueType.bv(source.width_bits),
                (value,),
                demand.blocks[block].effects[0].origin,
                (
                    source.bit_offset + source.width_bits - 1,
                    source.bit_offset,
                ),
            )
            for value in full
        )

