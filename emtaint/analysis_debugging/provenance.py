"""Read-only, source-preserving provenance indexes over canonical CIR.

The CIR wire schema is deliberately unchanged.  Frontends capture VEX and
machine-instruction metadata in additive debug sidecars; this module joins
those records to existing OriginMap entries and CIR definitions.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from types import MappingProxyType
from typing import Iterable, Mapping

from emtaint.core.contracts import Assessment, Origin, ValueRef
from emtaint.ir.canonical import (
    CIRFunction,
    CIRModule,
    CallEffect,
    Compute,
    LoadEffect,
    ReadRegister,
)


@dataclass(frozen=True, slots=True)
class SourceHint:
    """Frontend detail captured while one CIR value is created."""

    value_id: str
    origin_id: str
    role: str
    vex_statement_kind: str | None = None
    vex_temporary: int | None = None
    register_offset: int | None = None
    register_name: str | None = None


@dataclass(frozen=True, slots=True)
class InstructionHint:
    """Exact instruction/statement context captured at the VEX lowering edge."""

    origin_id: str
    function_rva: int
    block_rva: int
    statement_index: int | None
    instruction_rva: int | None
    source_opcode: str
    vex_statement_text: str | None = None
    instruction_bytes_hex: str | None = None
    assembly_text: str | None = None
    mode: str | None = None


@dataclass(frozen=True, slots=True)
class ValueDefinition:
    """One CIR effect defining a ValueRef and its direct input values."""

    value_id: str
    effect_kind: str
    origin_id: str
    block_rva: int
    effect_index: int
    input_value_ids: tuple[str, ...]
    operation: str
    operand_descriptions: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ValueOrigin:
    """Resolved source evidence for a value, preserving all known origins."""

    value_id: str
    origin: Origin
    role: str
    vex_statement_kind: str | None
    vex_temporary: int | None
    register_offset: int | None
    register_name: str | None
    instruction: InstructionHint | None


def _type_description(value_type: object) -> str:
    """Render the existing CIR type without inventing a source-level type."""

    kind = getattr(getattr(value_type, "kind", None), "value", "unknown")
    bits = getattr(value_type, "bits", None)
    signedness = getattr(getattr(value_type, "signedness", None), "value", None)
    suffix = "" if signedness is None else " " + signedness
    return f"{kind}{bits}{suffix}"


def _effect_operands(effect: object) -> tuple[object, ...]:
    """Return direct CIR operands for a definition, not transitive values."""

    if isinstance(effect, Compute):
        return effect.args
    if isinstance(effect, LoadEffect):
        return (effect.address, effect.guard)
    if isinstance(effect, CallEffect):
        return (*effect.arguments, effect.guard)
    return ()


def _operation_name(effect: object) -> str:
    """Return the exact operation represented by one CIR effect."""

    if isinstance(effect, Compute):
        return effect.op.value
    if isinstance(effect, LoadEffect):
        return "load"
    if isinstance(effect, ReadRegister):
        return "read-register " + effect.source.register
    if isinstance(effect, CallEffect):
        target = effect.target
        name = getattr(target, "symbol", None) or getattr(
            getattr(target, "function", None), "rva", None
        )
        return "call" if name is None else f"call {name}"
    return type(effect).__name__.replace("Effect", "").lower()


def _operand_description(operand: object) -> str:
    """Describe a CIR operand without guessing a variable name."""

    if isinstance(operand, ValueRef):
        return f"ValueRef({operand.id}, {_type_description(operand.type)})"
    if hasattr(operand, "value") and hasattr(operand, "type"):
        return (
            f"Constant({getattr(operand, 'value')!r}, "
            f"{_type_description(getattr(operand, 'type'))})"
        )
    return type(operand).__name__


def _value_inputs(effect: object) -> tuple[str, ...]:
    """Return direct ValueRef inputs carried by one defining effect."""

    return tuple(
        operand.id
        for operand in _effect_operands(effect)
        if isinstance(operand, ValueRef)
    )


def _defined_values(effect: object) -> tuple[ValueRef, ...]:
    """Return values defined by a CIR effect under the canonical contract."""

    if isinstance(effect, (Compute, LoadEffect, ReadRegister)):
        return (effect.result,)
    if isinstance(effect, CallEffect):
        return effect.results
    return ()


class ProvenanceIndex:
    """Immutable bidirectional index over CIR, VEX hints and instruction hints."""

    def __init__(
        self,
        module: CIRModule,
        source_hints: Iterable[SourceHint] = (),
        instruction_hints: Iterable[InstructionHint] = (),
    ) -> None:
        """Join sidecar hints to declared values and OriginMap records."""

        source_hint_records = tuple(source_hints)
        instruction_hint_records = tuple(instruction_hints)
        origin_by_id = {origin.id: origin for origin in module.origin_map}
        hints_by_value: dict[str, list[SourceHint]] = defaultdict(list)
        for hint in source_hint_records:
            if hint.origin_id not in origin_by_id:
                raise ValueError(
                    "Source hint names undeclared origin: " + hint.origin_id
                )
            hints_by_value[hint.value_id].append(hint)

        instruction_by_origin: dict[str, InstructionHint] = {}
        for hint in instruction_hint_records:
            if hint.origin_id not in origin_by_id:
                raise ValueError(
                    "Instruction hint names undeclared origin: " + hint.origin_id
                )
            previous = instruction_by_origin.get(hint.origin_id)
            if previous is not None and previous != hint:
                raise ValueError(
                    "Conflicting instruction hints for origin: " + hint.origin_id
                )
            instruction_by_origin[hint.origin_id] = hint

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
                            _operation_name(effect),
                            tuple(
                                _operand_description(operand)
                                for operand in _effect_operands(effect)
                            ),
                        )
                        definitions_by_value[value.id].append(definition)
                        if value.id not in values_by_origin[effect.origin]:
                            values_by_origin[effect.origin].append(value.id)
                        if isinstance(effect, ReadRegister):
                            register_names[(value.id, effect.origin)] = (
                                effect.source.register
                            )

        for value_id in values:
            definitions = definitions_by_value.get(value_id, ())
            hints = hints_by_value.get(value_id, ())
            origin_ids = tuple(
                dict.fromkeys(
                    (
                        *[item.origin_id for item in definitions],
                        *[item.origin_id for item in hints],
                    )
                )
            )
            for origin_id in origin_ids:
                matching = [
                    hint for hint in hints if hint.origin_id == origin_id
                ]
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
                            hint.vex_statement_kind or origin.source_opcode,
                            hint.vex_temporary,
                            hint.register_offset,
                            register_name,
                            instruction_by_origin.get(origin_id),
                        )
                    )
                    if value_id not in values_by_origin[origin_id]:
                        values_by_origin[origin_id].append(value_id)
                    instruction_rva = origin.point.instruction_rva
                    if instruction_rva is not None:
                        key = (
                            origin.point.function.binary.sha256,
                            instruction_rva,
                        )
                        if value_id not in values_by_instruction[key]:
                            values_by_instruction[key].append(value_id)

        self.module = module
        self._source_hints = source_hint_records
        self._instruction_hints = instruction_hint_records
        self._values: Mapping[str, ValueRef] = MappingProxyType(values)
        self._origins: Mapping[str, Origin] = MappingProxyType(origin_by_id)
        self._instruction_by_origin: Mapping[str, InstructionHint] = (
            MappingProxyType(instruction_by_origin)
        )
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

    @classmethod
    def for_function_with_architecture(
        cls,
        function: CIRFunction,
        origins: Iterable[Origin],
        architecture: object,
        source_hints: Iterable[SourceHint] = (),
        instruction_hints: Iterable[InstructionHint] = (),
    ) -> "ProvenanceIndex":
        """Build a one-function view while retaining optional captured hints."""

        owned_origins = tuple(
            origin
            for origin in origins
            if origin.point.function == function.function_id
        )
        if not owned_origins:
            raise ValueError("Function has no declared origins")
        module = CIRModule(
            owned_origins[0].producer,
            architecture,
            architecture.endian,
            function.function_id.binary.sha256,
            (function,),
            owned_origins,
            ("typed-effects",),
            Assessment(),
        )
        return cls(module, source_hints, instruction_hints)

    @property
    def source_hints(self) -> tuple[SourceHint, ...]:
        """Return immutable frontend value hints."""

        return self._source_hints

    @property
    def instruction_hints(self) -> tuple[InstructionHint, ...]:
        """Return immutable frontend instruction/statement hints."""

        return self._instruction_hints

    @property
    def source_hints_available(self) -> bool:
        """Whether the acquisition supplied value-level source hints."""

        return bool(self._source_hints)

    @property
    def instruction_hints_available(self) -> bool:
        """Whether the acquisition supplied exact instruction-level hints."""

        return bool(self._instruction_hints)

    def origin_record(self, origin_id: str) -> Origin | None:
        """Return one declared OriginMap record without issuing a query."""

        return self._origins.get(origin_id)

    def instruction_record(self, origin_id: str) -> InstructionHint | None:
        """Return the captured VEX/machine-instruction record for an origin."""

        return self._instruction_by_origin.get(origin_id)

    def value(self, value: ValueRef | str) -> ValueRef | None:
        """Return a declared value, or None for an unknown identifier."""

        value_id = value.id if isinstance(value, ValueRef) else value
        return self._values.get(value_id)

    def definitions(self, value: ValueRef | str) -> tuple[ValueDefinition, ...]:
        """Return every CIR definition associated with a value."""

        value_id = value.id if isinstance(value, ValueRef) else value
        return self._definitions_by_value.get(value_id, ())

    def origins(self, value: ValueRef | str) -> tuple[ValueOrigin, ...]:
        """Return all declared and frontend-captured origins for a value."""

        value_id = value.id if isinstance(value, ValueRef) else value
        return self._origins_by_value.get(value_id, ())

    def values_for_origin(self, origin_id: str) -> tuple[ValueRef, ...]:
        """Reverse-query values associated with one OriginMap record."""

        return tuple(
            self._values[value_id]
            for value_id in self._values_by_origin.get(origin_id, ())
        )

    def values_for_instruction(
        self, binary_sha256: str, instruction_rva: int
    ) -> tuple[ValueRef, ...]:
        """Reverse-query values created at one exact BinaryId/RVA pair."""

        return tuple(
            self._values[value_id]
            for value_id in self._values_by_instruction.get(
                (binary_sha256, instruction_rva), ()
            )
        )

    def instructions_for_rva(
        self, binary_sha256: str, instruction_rva: int
    ) -> tuple[InstructionHint, ...]:
        """Return all VEX statements captured at one machine instruction."""

        return tuple(
            hint
            for hint in self._instruction_hints
            if hint.instruction_rva == instruction_rva
            and self._origins[hint.origin_id].point.function.binary.sha256
            == binary_sha256
        )
