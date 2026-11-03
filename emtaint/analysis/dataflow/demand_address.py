"""Proof-carrying address normalization for demand analysis."""

from dataclasses import dataclass

from emtaint.core.contracts import Constant, ValueRef
from emtaint.ir.canonical import Compute, ReadRegister, WriteRegister
from emtaint.memory import AccessRoot


@dataclass(frozen=True)
class AddressProof:
    """A stable root/offset binding and the rules that established it."""

    root: AccessRoot
    offset: int | None
    provenance: tuple[str, ...]

    @property
    def binding(self) -> tuple[AccessRoot, int | None]:
        """Return the existing MemoryQueryPort binding shape."""

        return self.root, self.offset


class DemandAddressNormalizer:
    """Normalize only address forms justified by CIR definitions.

    This component intentionally does not turn an unknown offset into an
    exact one.  Consumers may use an ``AddressProof`` for MustAlias only when
    its offset is concrete and all other alias requirements also hold.
    """

    def __init__(self, owner) -> None:
        self.owner = owner

    def exact_stack_address(
        self,
        operand: Constant | ValueRef,
        seen: frozenset[str] = frozenset(),
    ) -> AddressProof | None:
        """Resolve copied constant offsets from an unchanged entry SP."""

        demand = self.owner
        if (
            hasattr(operand, "id")
            and operand.id not in seen
            and operand.id in demand.defs
        ):
            block, index, effect = demand.defs[operand.id]
            next_seen = seen | {operand.id}
            if isinstance(effect, ReadRegister):
                name = effect.source.register
                definitions, entry = demand.reaching(block, index, name)
                stack_pointer = demand.function.abi.stack_pointer or "sp"
                if (
                    name == stack_pointer
                    and not definitions
                    and entry
                ):
                    binding = dict(demand.initial.addresses).get(
                        "reg:" + stack_pointer
                    )
                    if binding is not None:
                        return AddressProof(
                            binding[0], binding[1], ("entry-sp",)
                        )
                if len(definitions) == 1 and not entry:
                    defined_block, cutoff = next(iter(definitions))
                    prior = demand.blocks[defined_block].effects[cutoff - 1]
                    if (
                        isinstance(prior, WriteRegister)
                        and prior.target.register == name
                        and prior.target.bit_offset == 0
                        and prior.target.width_bits
                        == prior.target.register_width_bits
                        and getattr(prior.guard, "value", None) is True
                    ):
                        proof = self.exact_stack_address(
                            prior.value, next_seen
                        )
                        if proof is not None:
                            return AddressProof(
                                proof.root,
                                proof.offset,
                                proof.provenance
                                + ("full-register-write:" + prior.origin,),
                            )
                return None
            if isinstance(effect, Compute) and effect.op.value == "copy":
                proof = self.exact_stack_address(
                    effect.args[0], next_seen
                )
                return self._append(proof, "copy:" + effect.origin)
            if isinstance(effect, Compute) and effect.op.value in (
                "add",
                "sub",
            ):
                if (
                    effect.op.value == "add"
                    and demand.literal(effect.args[0]) == 0
                ):
                    proof = self.exact_stack_address(
                        effect.args[1], next_seen
                    )
                    return self._append(
                        proof, "zero-add:" + effect.origin
                    )
                delta = demand.literal(effect.args[1])
                if type(delta) is int:
                    proof = self.exact_stack_address(
                        effect.args[0], next_seen
                    )
                    if proof is not None:
                        if proof.offset is None:
                            offset = None
                        else:
                            width = demand.port.engine.architecture.pointer_bits
                            signed_delta = (
                                delta
                                if effect.op.value == "add"
                                else -delta
                            )
                            offset = (proof.offset + signed_delta) % (1 << width)
                        return AddressProof(
                            proof.root,
                            offset,
                            proof.provenance
                            + (
                                effect.op.value
                                + "-constant:"
                                + effect.origin,
                            ),
                        )
        if isinstance(operand, Constant):
            from emtaint.analysis.dataflow.legacy_demand import LegacyDemand

            binding = LegacyDemand.local_address(demand, operand, seen)
            if binding is not None:
                return AddressProof(
                    binding[0], binding[1], ("absolute-constant",)
                )
        return None

    def entry_stack_binding(self, reference):
        """Bind a concrete sentinel-relative SSE value to the ABI stack root.

        This preserves the legacy entry-frame convention while using the
        function's declared stack-pointer register instead of assuming ARM
        register names.
        """

        demand = self.owner
        stack_pointer = demand.function.abi.stack_pointer or "sp"
        addresses = dict(demand.initial.addresses)
        registers = dict(demand.initial.registers)
        binding = addresses.get("reg:" + stack_pointer)
        entry = registers.get(stack_pointer)
        absolute = demand.port.concrete(reference)
        base = demand.port.concrete(entry) if entry is not None else None
        if (
            binding is None
            or type(absolute) is not int
            or type(base) is not int
        ):
            return None
        pointer_bits = demand.port.engine.architecture.pointer_bits
        modulus = 1 << pointer_bits
        delta = (absolute - base) % modulus
        signed_delta = (delta + modulus // 2) % modulus - modulus // 2
        if not -0x100000 <= signed_delta <= 0x100000:
            return None
        return binding[0], delta

    @staticmethod
    def _append(
        proof: AddressProof | None, rule: str
    ) -> AddressProof | None:
        if proof is None:
            return None
        return AddressProof(
            proof.root, proof.offset, proof.provenance + (rule,)
        )

