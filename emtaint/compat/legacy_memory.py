"""P1 legacy marker description, not executable memory semantics or lowering."""
from dataclasses import dataclass
from emtaint.solver.port import Term


@dataclass(frozen=True)
class LegacyMemoryMarker:
    kind: str
    address: Term
    address_bits: int
    value_bits: int
    missing_semantics: tuple[str, ...]


def describe_marker(kind, address, value_bits):
    if kind not in ("Load", "Store") or not isinstance(address, Term) or address.width is None:
        raise ValueError("Expected a legacy memory marker with a BV address")
    if type(value_bits) is not int or value_bits < 1:
        raise ValueError("Invalid legacy memory width")
    missing = ("endianness", "memory_version", "guard", "origin")
    if kind == "Store":
        missing += ("stored_value",)
    return LegacyMemoryMarker(kind, address, address.width, value_bits, missing)
