"""BinaryId/RVA address index and independent IDA debug sidecar export."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
from pathlib import Path

from emtaint.core import BinaryId

from .provenance import ProvenanceIndex


DEBUG_SIDECAR_VERSION = "Analysis-Debug-Sidecar-v1"


def _binary_sha256(binary: BinaryId | str) -> str:
    """Normalize a BinaryId without accepting ambiguous address identities."""

    if isinstance(binary, BinaryId):
        return binary.sha256
    return BinaryId(binary).sha256


def ida_effective_address(image_base: int, instruction_rva: int) -> int:
    """Translate an explicit image-relative address to an IDA effective address."""

    if type(image_base) is not int or image_base < 0:
        raise ValueError("IDA image base must be a non-negative integer")
    if type(instruction_rva) is not int or instruction_rva < 0:
        raise ValueError("Instruction RVA must be a non-negative integer")
    return image_base + instruction_rva


@dataclass(frozen=True, slots=True)
class IdaAddressRecord:
    """One exact OriginMap statement projected into an IDA address space."""

    binary_sha256: str
    function_rva: int
    block_rva: int
    statement_index: int | None
    instruction_rva: int
    ida_ea: int
    origin_id: str
    source_opcode: str
    value_ids: tuple[str, ...]
    vex_temporaries: tuple[int, ...]
    registers: tuple[tuple[int | None, str | None], ...]
    vex_statement_text: str | None = None
    instruction_bytes_hex: str | None = None
    assembly_text: str | None = None
    mode: str | None = None


class IdaAddressIndex:
    """Read-only BinaryId/RVA and IDA-EA reverse index over provenance."""

    def __init__(self, provenance: ProvenanceIndex, image_base: int) -> None:
        if type(image_base) is not int or image_base < 0:
            raise ValueError("IDA image base must be a non-negative integer")
        self.provenance = provenance
        self.image_base = image_base
        records: list[IdaAddressRecord] = []
        for origin in provenance.module.origin_map:
            point = origin.point
            if point.instruction_rva is None:
                continue
            values = provenance.values_for_origin(origin.id)
            value_origins = tuple(
                item
                for value in values
                for item in provenance.origins(value)
                if item.origin.id == origin.id
            )
            temporaries = tuple(
                sorted({
                    item.vex_temporary
                    for item in value_origins
                    if item.vex_temporary is not None
                })
            )
            registers = tuple(sorted(
                {
                    (item.register_offset, item.register_name)
                    for item in value_origins
                    if item.register_offset is not None
                    or item.register_name is not None
                },
                key=lambda item: (
                    -1 if item[0] is None else item[0],
                    "" if item[1] is None else item[1],
                ),
            ))
            instruction = provenance.instruction_record(origin.id)
            records.append(IdaAddressRecord(
                point.function.binary.sha256,
                point.function.rva,
                point.block.rva,
                point.statement,
                point.instruction_rva,
                ida_effective_address(image_base, point.instruction_rva),
                origin.id,
                origin.source_opcode,
                tuple(value.id for value in values),
                temporaries,
                registers,
                None if instruction is None else instruction.vex_statement_text,
                None if instruction is None else instruction.instruction_bytes_hex,
                None if instruction is None else instruction.assembly_text,
                None if instruction is None else instruction.mode,
            ))
        self._records = tuple(sorted(
            records,
            key=lambda item: (
                item.binary_sha256,
                item.instruction_rva,
                -1 if item.statement_index is None else item.statement_index,
                item.origin_id,
            ),
        ))

    def records(self) -> tuple[IdaAddressRecord, ...]:
        """Return every address record in stable RVA/statement order."""

        return self._records

    def by_rva(
        self, binary: BinaryId | str, instruction_rva: int
    ) -> tuple[IdaAddressRecord, ...]:
        """Look up all statements and CIR values at a BinaryId/RVA pair."""

        binary_sha256 = _binary_sha256(binary)
        return tuple(
            record
            for record in self._records
            if record.binary_sha256 == binary_sha256
            and record.instruction_rva == instruction_rva
        )

    def by_ida_ea(
        self, binary: BinaryId | str, ida_ea: int
    ) -> tuple[IdaAddressRecord, ...]:
        """Reverse an IDA EA using this index's explicit image base."""

        if type(ida_ea) is not int or ida_ea < self.image_base:
            return ()
        return self.by_rva(binary, ida_ea - self.image_base)

    def export(self, path: str | Path) -> None:
        """Exclusively create the additive, rebuildable JSON debug sidecar."""

        reverse_index: dict[str, list[str]] = {}
        for record in self._records:
            reverse_index.setdefault(hex(record.ida_ea), []).append(
                record.origin_id
            )
        payload = {
            "schema_version": DEBUG_SIDECAR_VERSION,
            "compatibility": {
                "cir_schema_version": self.provenance.module.schema_version,
                "storage": "independent-additive-sidecar",
                "migration": (
                    "No CIR migration. Rebuild this sidecar from the CIR module "
                    "and frontend source hints when the debug schema changes."
                ),
            },
            "binary_sha256": self.provenance.module.binary_sha256,
            "image_base": self.image_base,
            "records": [asdict(record) for record in self._records],
            "ida_ea_to_origin_ids": reverse_index,
        }
        destination = Path(path)
        with destination.open("x", encoding="utf8", newline="\n") as stream:
            json.dump(payload, stream, indent=2, sort_keys=True)
            stream.write("\n")
