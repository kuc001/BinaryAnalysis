"""Read-only CIR provenance sidecar built from declared origins and effects.

The CIR wire schema intentionally remains unchanged.  This module derives the
parts already represented by ``CIRModule.origin_map`` and accepts source hints
captured by a frontend at the instant a value is created.  It never infers a
VEX temporary or register from the textual ``ValueRef.id``.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping

from emtaint.core.contracts import Origin, ValueRef
from emtaint.ir.canonical import (
    CIRModule,
    CallEffect,
    Compute,
    LoadEffect,
    ReadRegister,
)


@dataclass(frozen=True, slots=True)
class SourceHint:
    """Frontend detail captured while one CIR value is being created."""

    value_id: str
    origin_id: str
    role: str
    vex_statement_kind: str | None = None
    vex_temporary: int | None = None
    register_offset: int | None = None
    register_name: str | None = None


@dataclass(frozen=True, slots=True)
class ValueDefinition:
    """One CIR effect that defines ``value_id`` and its direct input values."""

    value_id: str
    effect_kind: str
    origin_id: str
    block_rva: int
    effect_index: int
    input_value_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValueOrigin:
    """Resolved source evidence for one value without changing its identity."""

    value_id: str
    origin: Origin
    role: str
    vex_statement_kind: str | None
    vex_temporary: int | None
    register_offset: int | None
    register_name: str | None


def _value_inputs(effect: object) -> tuple[str, ...]:
    """Return direct ValueRef inputs carried by one defining CIR effect."""

    operands: tuple[object, ...]
    if isinstance(effect, Compute):
        operands = effect.args
    elif isinstance(effect, LoadEffect):
        operands = (effect.address, effect.guard)
    elif isinstance(effect, CallEffect):
        operands = (*effect.arguments, effect.guard)
    else:
        operands = ()
    return tuple(
        operand.id for operand in operands if isinstance(operand, ValueRef)
    )


def _defined_values(effect: object) -> tuple[ValueRef, ...]:
    """Return values defined by a CIR effect using the existing CIR contract."""

    if isinstance(effect, (Compute, LoadEffect, ReadRegister)):
        return (effect.result,)
    if isinstance(effect, CallEffect):
        return effect.results
    return ()


class ProvenanceIndex:
    """Bidirectional, immutable query view over CIR and frontend provenance."""

    def __init__(
        self,
        module: CIRModule,
        source_hints: Iterable[SourceHint] = (),
    ) -> None:
        """Index declared definitions and source hints without mutating CIR."""

        origin_by_id = {origin.id: origin for origin in module.origin_map}
        hints_by_value: dict[str, list[SourceHint]] = defaultdict(list)
        for hint in source_hints:
            if hint.origin_id not in origin_by_id:
                raise ValueError(
                    "Source hint names undeclared origin: " + hint.origin_id
                )
            hints_by_value[hint.value_id].append(hint)

        values = {
            value.id: value
            for function in module.functions
            for value in function.values
        }
        definitions_by_value: dict[str, list[ValueDefinition]] = defaultdict(list)
        register_names: dict[tuple[str, str], str] = {}
        values_by_origin: dict[str, list[str]] = defaultdict(list)
        values_by_instruction: dict[tuple[str, int], list[str]] = defaultdict(list)
        origins_by_value: dict[str, list[ValueOrigin]] = defaultdict(list)

        for function in module.functions:
            for block in function.blocks:
                for effect_index, effect in enumerate(block.effects):
                    for value in _defined_values(effect):
                        definition = ValueDefinition(
                            value.id,
                            type(effect).__name__,
                            effect.origin,
                            block.id.rva,
                            effect_index,
                            _value_inputs(effect),
                        )
                        definitions_by_value[value.id].append(definition)
                        if value.id not in values_by_origin[effect.origin]:
                            values_by_origin[effect.origin].append(value.id)
                        if isinstance(effect, ReadRegister):
                            register_names[(value.id, effect.origin)] = (
                                effect.source.register
                            )

        for value_id, value in values.items():
            definitions = definitions_by_value.get(value_id, ())
            origin_ids = tuple(dict.fromkeys(item.origin_id for item in definitions))
            hints = hints_by_value.get(value_id, ())
            for origin_id in origin_ids:
                matching = [hint for hint in hints if hint.origin_id == origin_id]
                detailed = [
                    hint
                    for hint in matching
                    if hint.role != "definition"
                    or hint.vex_temporary is not None
                    or hint.register_offset is not None
                    or hint.register_name is not None
                ]
                if detailed:
                    matching = detailed
                if not matching:
                    matching = [SourceHint(value_id, origin_id, "definition")]
                for hint in matching:
                    origin = origin_by_id[origin_id]
                    register_name = hint.register_name
                    if register_name is None:
                        register_name = register_names.get((value_id, origin_id))
                    origins_by_value[value_id].append(
                        ValueOrigin(
                            value_id,
                            origin,
                            hint.role,
                            hint.vex_statement_kind,
                            hint.vex_temporary,
                            hint.register_offset,
                            register_name,
                        )
                    )
                    instruction_rva = origin.point.instruction_rva
                    if instruction_rva is not None:
                        key = (origin.point.function.binary.sha256, instruction_rva)
                        if value_id not in values_by_instruction[key]:
                            values_by_instruction[key].append(value_id)

        self.module = module
        self._values: Mapping[str, ValueRef] = MappingProxyType(values)
        self._origins: Mapping[str, Origin] = MappingProxyType(origin_by_id)
        self._definitions_by_value = MappingProxyType(
            {key: tuple(items) for key, items in definitions_by_value.items()}
        )
        self._origins_by_value = MappingProxyType(
            {key: tuple(items) for key, items in origins_by_value.items()}
        )
        self._values_by_origin = MappingProxyType(
            {key: tuple(items) for key, items in values_by_origin.items()}
        )
        self._values_by_instruction = MappingProxyType(
            {key: tuple(items) for key, items in values_by_instruction.items()}
        )

    def value(self, value: ValueRef | str) -> ValueRef | None:
        """Return a declared value, or ``None`` for an unknown identifier."""

        value_id = value.id if isinstance(value, ValueRef) else value
        return self._values.get(value_id)

    def definitions(self, value: ValueRef | str) -> tuple[ValueDefinition, ...]:
        """Return every CIR definition associated with a value."""

        value_id = value.id if isinstance(value, ValueRef) else value
        return self._definitions_by_value.get(value_id, ())

    def origins(self, value: ValueRef | str) -> tuple[ValueOrigin, ...]:
        """Return every declared source of a value, including synthetic ones."""

        value_id = value.id if isinstance(value, ValueRef) else value
        return self._origins_by_value.get(value_id, ())

    def values_for_origin(self, origin_id: str) -> tuple[ValueRef, ...]:
        """Reverse-query values defined by one existing OriginMap record."""

        return tuple(
            self._values[value_id]
            for value_id in self._values_by_origin.get(origin_id, ())
        )

    def values_for_instruction(
        self, binary_sha256: str, instruction_rva: int
    ) -> tuple[ValueRef, ...]:
        """Reverse-query values created at an exact binary/RVA pair."""

        return tuple(
            self._values[value_id]
            for value_id in self._values_by_instruction.get(
                (binary_sha256, instruction_rva), ()
            )
        )
