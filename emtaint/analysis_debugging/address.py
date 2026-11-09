"""Explicit BinaryId-scoped address translation for debug presentation."""
from __future__ import annotations
from dataclasses import dataclass
from emtaint.core import BinaryId

@dataclass(frozen=True, slots=True)
class AddressView:
    """Canonical RVA and optional external address projections."""
    rva: int | None
    ida_va: int | None
    runtime_va: int | None
    reason: str | None = None

class AddressTranslator:
    """Translate canonical RVAs without changing analysis identities."""
    def __init__(self, binary: BinaryId | str, *, ida_image_base: int | None = None,
                 runtime_base: int | None = None, address_bits: int = 64) -> None:
        if type(address_bits) is not int or not 1 <= address_bits <= 128:
            raise ValueError("address_bits must be in 1..128")
        self.binary_sha256 = binary.sha256 if isinstance(binary, BinaryId) else BinaryId(binary).sha256
        self.maximum = (1 << address_bits) - 1
        for name, base in (("IDA image base", ida_image_base), ("runtime base", runtime_base)):
            if base is not None and (type(base) is not int or not 0 <= base <= self.maximum):
                raise ValueError(f"{name} is outside the configured address width")
        self.ida_image_base, self.runtime_base = ida_image_base, runtime_base

    def _check_binary(self, binary: BinaryId | str) -> None:
        sha = binary.sha256 if isinstance(binary, BinaryId) else BinaryId(binary).sha256
        if sha != self.binary_sha256: raise ValueError("Address mapping belongs to another BinaryId")

    def _check_rva(self, rva: int) -> None:
        if type(rva) is not int or not 0 <= rva <= self.maximum:
            raise ValueError("RVA is outside the configured address width")

    def to_ida_va(self, binary: BinaryId | str, rva: int) -> int | None:
        """Translate an image-relative address using the user's IDA base."""
        self._check_binary(binary); self._check_rva(rva)
        if self.ida_image_base is None: return None
        value = self.ida_image_base + rva
        return value if value <= self.maximum else None

    def to_runtime_va(self, binary: BinaryId | str, rva: int) -> int | None:
        """Translate using a runtime base independent of IDA."""
        self._check_binary(binary); self._check_rva(rva)
        if self.runtime_base is None: return None
        value = self.runtime_base + rva
        return value if value <= self.maximum else None

    def to_rva(self, binary: BinaryId | str, ida_va: int) -> int | None:
        """Reverse an IDA EA using the configured IDA base."""
        self._check_binary(binary)
        if type(ida_va) is not int or not 0 <= ida_va <= self.maximum:
            raise ValueError("IDA VA is outside the configured address width")
        if self.ida_image_base is None or ida_va < self.ida_image_base: return None
        return ida_va - self.ida_image_base

    def view(self, binary: BinaryId | str, rva: int | None) -> AddressView:
        """Return all configured projections for one canonical RVA."""
        self._check_binary(binary)
        if rva is None: return AddressView(None, None, None, "INSTRUCTION_RVA_NOT_RECORDED")
        self._check_rva(rva)
        ida, runtime = self.to_ida_va(binary, rva), self.to_runtime_va(binary, rva)
        reason = None if ida is not None else (
            "IDA_IMAGE_BASE_NOT_CONFIGURED" if self.ida_image_base is None else "IDA_ADDRESS_OVERFLOW")
        return AddressView(rva, ida, runtime, reason)

    def format_address(self, binary: BinaryId | str, rva: int | None,
                       label: str = "Address") -> str:
        """Format IDA VA first and preserve the canonical RVA."""
        view = self.view(binary, rva)
        if view.rva is None: return f"{label}: unavailable ({view.reason})"
        if view.ida_va is None:
            return f"{label}: RVA 0x{view.rva:x}; IDA VA unavailable ({view.reason})"
        result = f"{label}: IDA VA 0x{view.ida_va:x} (RVA 0x{view.rva:x})"
        if view.runtime_va is not None: result += f"; Runtime VA 0x{view.runtime_va:x}"
        return result
