"""P6 CIR transfer subset of legacy ``AccurateDataFlow`` action families.

This is not the full old trace engine. Unsupported families retain explicit
unknown/havoc; default legacy selection is not replaced by this experiment.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
import logging
from collections.abc import Mapping

from emtaint.analysis.framework.state import FlowState
from emtaint.core.contracts import Assessment, Constant, TypeKind, ValueType
from emtaint.debugging import EventSampler
from emtaint.ir.canonical import (
    CallEffect,
    Compute,
    DirectTarget,
    HavocEffect,
    LoadEffect,
    ReadRegister,
    RegisterWritePolicy,
    StoreEffect,
    UnknownEffect,
    WriteRegister,
)
from emtaint.memory import SymbolicOp
from emtaint.memory.engine import combine, over


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class ProcedureSummary:
    """Minimal validated call result and write-footprint summary."""

    argument_index: int | None
    write_regions: tuple[str, ...]
    proof: str

    @classmethod
    def identity(cls, index: int, proof: str) -> "ProcedureSummary":
        """Create a summary returning the argument at ``index`` unchanged."""

        if type(index) is not int or index < 0 or not proof:
            raise ValueError("Summary needs argument/proof")
        return cls(index, (), proof)


class CIRAccurateDataFlow:
    """Execute pure CIR effects over versioned SSE, registers and memory.

    Args:
        port: Function/context-scoped MemoryRuntimePort.
        summaries: Optional direct-callee summaries keyed by function identity.
    """

    def __init__(
        self,
        port: object,
        summaries: Mapping[object, ProcedureSummary] | None = None,
    ) -> None:
        self.port = port
        self.summaries = dict(summaries or {})
        self.diagnostics: list[str] = []
        self._events = EventSampler(LOGGER)

    def initial(self) -> FlowState:
        """Create the entry flow state from the port's initial memory image."""

        self.port.validate_current()
        state = FlowState(
            self.port.initial,
            self.port.scope.context,
            addresses=tuple(self.port.seed_addresses.items()),
            assessment=Assessment.complete(),
        )
        self._events.emit(
            "dataflow.state.initialized",
            memory=str(state.memory),
            addresses=len(state.addresses),
            context=str(state.context),
        )
        return state

    def operand(
        self,
        state: FlowState,
        value: object,
        origin: str,
    ) -> object:
        """Resolve a CIR constant or SSA value to an SSE expression ID."""

        if isinstance(value, Constant):
            return self.port.constant(value.value, value.type, origin)
        values = dict(state.values)
        if value.id not in values:
            diagnostic = "Undefined CIR value: " + value.id
            self.diagnostics.append(diagnostic)
            self._events.emit(
                "dataflow.operand.undefined",
                value=value.id,
                origin=origin,
            )
            return self.port.unknown(
                value.type,
                origin,
                "Undefined CIR value " + value.id,
            )
        return values[value.id]

    def as_bv(self, value: object, origin: str) -> object:
        """Convert pointer-typed SSE values to same-width bitvectors."""

        type_ = self.port.type_of(value)
        if type_.kind != TypeKind.POINTER:
            return value
        return self.port.operation(
            SymbolicOp.SUB,
            ValueType.bv(type_.bits),
            (value, self.port.constant(0, type_, origin)),
            origin,
        )

    def as_type(
        self,
        value: object,
        type_: ValueType,
        origin: str,
    ) -> object:
        """Apply the explicit pointer/bitvector conversion allowed by CIR."""

        value_type = self.port.type_of(value)
        if value_type == type_:
            return value
        if type_.kind == TypeKind.POINTER and value_type == ValueType.bv(type_.bits):
            return self.port.operation(
                SymbolicOp.ADD,
                type_,
                (self.port.constant(0, type_, origin), value),
                origin,
            )
        raise ValueError("CIR transfer value sort mismatch")

    def transfer(self, state: FlowState, effect: object) -> FlowState:
        """Apply one non-control CIR effect and return an immutable flow state."""

        self.port.validate_current()
        port = self.port
        origin = effect.origin
        values = dict(state.values)
        registers = dict(state.registers)
        addresses = dict(state.addresses)
        state = replace(state, point=port.point(origin))
        assessment = state.assessment
        memory = state.memory
        register_epoch = state.register_epoch

        self._events.emit(
            "dataflow.transfer.started",
            effect=type(effect).__name__,
            origin=origin,
            memory=str(memory),
            values=len(values),
            registers=len(registers),
            address_bindings=len(addresses),
        )

        def operand(value: object) -> object:
            """Resolve an operand in the current input state."""

            return self.operand(state, value, origin)

        def truth() -> object:
            """Create the canonical true guard for this effect origin."""

            return port.constant(True, ValueType.boolean(), origin)

        def update_value(
            name: str,
            reference: object,
            binding: tuple[object, int] | None = None,
        ) -> None:
            """Update one SSA value and its optional APG address binding."""

            values[name] = reference
            addresses.pop(name, None)
            if binding is not None:
                addresses[name] = binding
            self._events.emit(
                "dataflow.value.updated",
                value=name,
                expression=str(reference),
                address_bound=binding is not None,
                origin=origin,
            )

        if isinstance(effect, Compute):
            args = tuple(operand(item) for item in effect.args)
            binding = None
            first = (
                addresses.get(effect.args[0].id)
                if hasattr(effect.args[0], "id")
                else None
            )
            if effect.op.value == "copy":
                binding = first
            elif effect.op.value in ("add", "sub"):
                offset = port.concrete(args[1])
                if first is not None and offset is not None:
                    root, base = first
                    delta = offset if effect.op.value == "add" else -offset
                    binding = (root, base + delta)
                elif (
                    effect.op.value == "add"
                    and port.concrete(args[0]) == 0
                    and hasattr(effect.args[1], "id")
                ):
                    binding = addresses.get(effect.args[1].id)
            update_value(
                effect.result.id,
                port.operation(
                    effect.op,
                    effect.result.type,
                    args,
                    origin,
                    effect.params,
                ),
                binding,
            )
        elif isinstance(effect, ReadRegister):
            source = effect.source
            full = registers.get(source.register)
            if full is None:
                full = port.symbol(
                    "register:"
                    + source.register
                    + ":epoch:"
                    + str(register_epoch),
                    ValueType.bv(source.register_width_bits),
                    origin,
                )
            value = full
            if (
                source.bit_offset
                or source.width_bits != source.register_width_bits
            ):
                value = port.operation(
                    SymbolicOp.EXTRACT,
                    ValueType.bv(source.width_bits),
                    (full,),
                    origin,
                    (
                        source.bit_offset + source.width_bits - 1,
                        source.bit_offset,
                    ),
                )
            binding = (
                addresses.get("reg:" + source.register)
                if source.bit_offset == 0
                and source.width_bits == source.register_width_bits
                else None
            )
            update_value(
                effect.result.id,
                self.as_type(value, effect.result.type, origin),
                binding,
            )
        elif isinstance(effect, WriteRegister):
            guard = operand(effect.guard)
            if port.concrete(guard) is False:
                return state
            target = effect.target
            width = target.register_width_bits
            old = registers.get(target.register)
            if old is None:
                old = port.symbol(
                    "register:"
                    + target.register
                    + ":epoch:"
                    + str(register_epoch),
                    ValueType.bv(width),
                    origin,
                )
            value = self.as_bv(operand(effect.value), origin)
            if effect.policy == RegisterWritePolicy.ZERO_UPPER:
                if width > target.width_bits:
                    value = port.operation(
                        SymbolicOp.ZERO_EXTEND,
                        ValueType.bv(width),
                        (value,),
                        origin,
                        (width - target.width_bits,),
                    )
            elif effect.policy == RegisterWritePolicy.PRESERVE_OTHERS:
                pieces = []
                high = target.bit_offset + target.width_bits
                if high < width:
                    pieces.append(
                        port.operation(
                            SymbolicOp.EXTRACT,
                            ValueType.bv(width - high),
                            (old,),
                            origin,
                            (width - 1, high),
                        )
                    )
                pieces.append(value)
                if target.bit_offset:
                    pieces.append(
                        port.operation(
                            SymbolicOp.EXTRACT,
                            ValueType.bv(target.bit_offset),
                            (old,),
                            origin,
                            (target.bit_offset - 1, 0),
                        )
                    )
                if len(pieces) > 1:
                    value = port.operation(
                        SymbolicOp.CONCAT,
                        ValueType.bv(width),
                        tuple(pieces),
                        origin,
                    )
            if port.concrete(guard) is not True:
                value = port.operation(
                    SymbolicOp.IF,
                    ValueType.bv(width),
                    (guard, value, old),
                    origin,
                )
            registers[target.register] = value
            addresses.pop("reg:" + target.register, None)
            if (
                effect.policy == RegisterWritePolicy.FULL
                and port.concrete(guard) is True
                and hasattr(effect.value, "id")
            ):
                binding = addresses.get(effect.value.id)
                if binding is not None:
                    addresses["reg:" + target.register] = binding
            self._events.emit(
                "dataflow.register.updated",
                register=target.register,
                expression=str(value),
                policy=effect.policy.value,
                guard=str(guard),
                origin=origin,
            )
        elif isinstance(effect, (LoadEffect, StoreEffect)):
            guard = operand(effect.guard)
            if port.concrete(guard) is False:
                return state
            location = port.location(
                effect.address,
                addresses,
                values,
                effect.width_bits,
                effect.endian,
                origin,
            )
            if isinstance(effect, StoreEffect):
                result = port.write(
                    memory,
                    location,
                    operand(effect.value),
                    guard,
                    origin,
                )
                memory = result.state
            else:
                result = port.read(memory, location, guard, origin)
                reference = self.as_type(
                    result.value,
                    effect.result.type,
                    origin,
                )
                if port.concrete(guard) is not True:
                    old = values.get(effect.result.id)
                    if old is None:
                        old = port.unknown(
                            effect.result.type,
                            origin,
                            "Unexecuted load has no prior value",
                        )
                    reference = port.operation(
                        SymbolicOp.IF,
                        effect.result.type,
                        (guard, reference, old),
                        origin,
                    )
                update_value(effect.result.id, reference)
            assessment = combine((assessment, result.assessment))
        elif isinstance(effect, UnknownEffect):
            if effect.may_write_registers:
                register_epoch += 1
            if effect.may_write_regions:
                memory = port.havoc(
                    memory,
                    effect.may_write_regions,
                    effect.reason,
                    origin,
                )
            if "*" in effect.may_write_registers:
                registers.clear()
                addresses = {
                    key: value
                    for key, value in addresses.items()
                    if not key.startswith("reg:")
                }
            else:
                for name in effect.may_write_registers:
                    registers.pop(name, None)
                    addresses.pop("reg:" + name, None)
            assessment = combine(
                (assessment, over(effect.source_opcode + ": " + effect.reason, True))
            )
            self._events.emit(
                "dataflow.unknown.applied",
                source_opcode=effect.source_opcode,
                reason=effect.reason,
                write_regions=list(effect.may_write_regions),
                write_registers=list(effect.may_write_registers),
                origin=origin,
            )
        elif isinstance(effect, (CallEffect, HavocEffect)):
            guard = operand(effect.guard)
            if port.concrete(guard) is False:
                return state
            summary = (
                self.summaries.get(effect.target.function)
                if isinstance(effect, CallEffect)
                and isinstance(effect.target, DirectTarget)
                else None
            )
            if summary is not None:
                regions = summary.write_regions
            elif isinstance(effect, CallEffect):
                regions = effect.footprint.write_regions
            else:
                regions = effect.regions
            if regions:
                memory = port.havoc(
                    memory,
                    regions,
                    "Call/explicit side effects",
                    origin,
                    guard,
                )
            if isinstance(effect, CallEffect):
                for result in effect.results:
                    if (
                        summary is not None
                        and summary.argument_index is not None
                        and summary.argument_index < len(effect.arguments)
                    ):
                        value = self.as_type(
                            operand(effect.arguments[summary.argument_index]),
                            result.type,
                            origin,
                        )
                    else:
                        value = port.unknown(
                            result.type,
                            origin,
                            "Call result without validated summary",
                        )
                    if summary is not None and (
                        summary.argument_index is None
                        or summary.argument_index >= len(effect.arguments)
                    ):
                        assessment = combine(
                            (assessment, over("Summary argument is unavailable", True))
                        )
                    if port.concrete(guard) is not True:
                        prior = values.get(result.id)
                        if prior is None:
                            prior = port.unknown(
                                result.type,
                                origin,
                                "Unexecuted call result",
                            )
                        value = port.operation(
                            SymbolicOp.IF,
                            result.type,
                            (guard, value, prior),
                            origin,
                        )
                    update_value(result.id, value)
                clobbers = effect.footprint.clobbered_registers
            else:
                clobbers = effect.registers
            if clobbers:
                register_epoch += 1
            if "*" in clobbers:
                registers.clear()
                addresses = {
                    key: value
                    for key, value in addresses.items()
                    if not key.startswith("reg:")
                }
            else:
                for name in clobbers:
                    registers.pop(name, None)
                    addresses.pop("reg:" + name, None)
            if summary is None:
                assessment = combine(
                    (
                        assessment,
                        over("Call/IR side effect lacks complete summary", True),
                    )
                )
            self._events.emit(
                "dataflow.call.applied",
                summary=summary is not None,
                results=len(effect.results) if isinstance(effect, CallEffect) else 0,
                write_regions=list(regions),
                clobbered_registers=list(clobbers),
                origin=origin,
            )
        else:
            raise TypeError(
                "Control effect must be handled by the worklist: "
                + type(effect).__name__
            )

        result_state = replace(
            state,
            memory=memory,
            values=tuple(sorted(values.items())),
            registers=tuple(sorted(registers.items())),
            addresses=tuple(sorted(addresses.items())),
            assessment=assessment,
            register_epoch=register_epoch,
        )
        self._events.emit(
            "dataflow.transfer.completed",
            effect=type(effect).__name__,
            origin=origin,
            memory_before=str(state.memory),
            memory_after=str(result_state.memory),
            values=len(result_state.values),
            registers=len(result_state.registers),
            address_bindings=len(result_state.addresses),
            register_epoch=register_epoch,
            completeness=result_state.assessment.status.value,
            precision=result_state.assessment.precision.value,
        )
        return result_state
