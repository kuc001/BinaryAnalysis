"""Classify CIR pointer values using the shared demand and memory engines."""

from dataclasses import dataclass
from time import perf_counter

from emtaint.core import Completeness
from emtaint.memory import AliasKind


@dataclass(frozen=True)
class AliasQueryResult:
    """One demand-driven pointer query with explicit precision status."""

    predicted: str
    alias_kinds: tuple[str, ...]
    evidence: tuple[str, ...]
    complete: bool
    reason_codes: tuple[str, ...]
    elapsed_seconds: float


def classify_alias_operands(
        demand, left_operand, right_operand, origin, *, width_bits: int = 8):
    """Return a pointer-alias decision from MemoryQueryPort, not an oracle."""
    return classify_alias_values(
        demand,
        demand.value(left_operand),
        demand.value(right_operand),
        origin,
        width_bits=width_bits,
    )


def classify_alias_values(
        demand, left_values, right_values, origin, *, width_bits: int = 8):
    """Classify two demand value sets at the same CIR program point."""

    if type(width_bits) is not int or width_bits <= 0 or width_bits % 8:
        raise ValueError("Alias query width must be a positive byte multiple")
    left_indexed = tuple(
        value for value in left_values
        if demand.address_normalizer.indexed_stack_address(value) is not None
    )
    right_indexed = tuple(
        value for value in right_values
        if demand.address_normalizer.indexed_stack_address(value) is not None
    )
    left_empty = tuple(
        value for value in left_values
        if demand.uninitialized_frame_pointer(value)
    )
    right_empty = tuple(
        value for value in right_values
        if demand.uninitialized_frame_pointer(value)
    )
    left = tuple(
        demand.address_binding(value) for value in left_values
        if value not in left_empty
    )
    right = tuple(
        demand.address_binding(value) for value in right_values
        if value not in right_empty
    )
    reasons = []
    if (not left and not left_empty) or (not right and not right_empty):
        reasons.append("NO_LOCATION_ALTERNATIVES")
    if any(binding is None for binding in left + right):
        reasons.append("ADDRESS_UNRESOLVED")
    if any(
            binding is not None and binding[1] is None
            for binding in left + right):
        reasons.append("OFFSET_UNRESOLVED")
    kinds = []
    evidence = []
    left_locations = []
    right_locations = []
    engine = demand.port.engine
    # The default queries address identity; a caller may request an access
    # interval by passing its actual bit width.
    address_identity_width = width_bits
    for binding in left:
        if binding is not None:
            left_locations.append(engine.location(
                *binding, address_identity_width,
                engine.architecture.endian, origin))
    for binding in right:
        if binding is not None:
            right_locations.append(engine.location(
                *binding, address_identity_width,
                engine.architecture.endian, origin))
    if any(
            location.assessment.status != Completeness.COMPLETE
            for location in left_locations + right_locations):
        reasons.append("LOCATION_INCOMPLETE")
    for left_location in left_locations:
        for right_location in right_locations:
            alias = demand.port.alias(
                demand.initial.memory, left_location, right_location
            )
            kinds.append(alias.kind)
            evidence.extend(alias.evidence or alias.assessment.precision_loss)
            if alias.assessment.status != Completeness.COMPLETE:
                reasons.append("ALIAS_INCOMPLETE")
    complete = not reasons
    canonical_left = {
        (location.object_id, location.byte_interval)
        for location in left_locations
    }
    canonical_right = {
        (location.object_id, location.byte_interval)
        for location in right_locations
    }
    if left_empty or right_empty:
        evidence.append(
            "Uninitialized local pointer contributes an empty points-to alternative"
        )
    if left_indexed or right_indexed:
        evidence.append(
            "Indexed stack address retains affine stride uncertainty"
        )
    if not complete:
        predicted = "INCOMPLETE"
        evidence.append("Alias query is incomplete")
    elif not left_locations or not right_locations:
        predicted = "NOALIAS"
    elif kinds and all(kind == AliasKind.NO for kind in kinds):
        predicted = "NOALIAS"
    elif (
            len(canonical_left) == len(canonical_right) == 1
            and kinds
            and all(kind == AliasKind.MUST for kind in kinds)
            and not left_empty
            and not right_empty
            and not left_indexed
            and not right_indexed):
        predicted = "MUSTALIAS"
    else:
        predicted = "MAYALIAS"
        if not kinds:
            evidence.append("No exact location pair was available")
        else:
            evidence.append("Target alternatives are not uniformly NO or uniquely MUST")
    return (
        predicted,
        tuple(kind.value for kind in kinds),
        tuple(dict.fromkeys(evidence)),
        complete,
        tuple(dict.fromkeys(reasons)),
    )


def query_alias(
        demand, left_operand, right_operand, origin, *, width_bits: int = 8
) -> AliasQueryResult:
    """Run the shared demand and MemoryQueryPort alias path for two CIR values."""

    started = perf_counter()
    result = classify_alias_operands(
        demand, left_operand, right_operand, origin, width_bits=width_bits
    )
    return AliasQueryResult(*result, perf_counter() - started)
