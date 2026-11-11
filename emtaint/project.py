"""F0 project input and binary address validation, without a native runtime."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from emtaint.core import BinaryId
from emtaint.frontends.inputs import ELFImage, InputError, Segment


PROJECT_SCHEMA = "ProjectSpec-F0-v1"
SUPPORTED_MACHINES = frozenset((3, 8, 40, 62, 183))


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for name, value in pairs:
        if name in result:
            raise InputError("Duplicate Project JSON key: " + name)
        result[name] = value
    return result


def _hex_address(value: object, field: str) -> int:
    if type(value) is not str or re.fullmatch(r"0x[0-9a-fA-F]+", value) is None:
        raise InputError(field + " must be a hexadecimal address string")
    address = int(value, 16)
    if address >= 1 << 64:
        raise InputError(field + " exceeds the 64-bit address domain")
    return address


@dataclass(frozen=True)
class ProjectSpec:
    """One binary, one angr-vex frontend and one selected function."""

    binary_path: Path
    binary_sha256: str
    frontend: str
    function_vas: tuple[int, ...]
    expected_image_base: int
    allow_partial: bool
    project_schema_version: str = PROJECT_SCHEMA

    def __post_init__(self) -> None:
        if self.project_schema_version != PROJECT_SCHEMA:
            raise InputError("Unsupported Project schema version")
        if not isinstance(self.binary_path, Path):
            raise InputError("Project binary path must be a Path")
        if (type(self.binary_sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", self.binary_sha256) is None):
            raise InputError("Project binary SHA-256 must be lowercase hex")
        if self.frontend != "angr-vex":
            raise InputError("F0 supports only the angr-vex frontend")
        if (type(self.function_vas) is not tuple or len(self.function_vas) != 1
                or type(self.function_vas[0]) is not int
                or not 0 <= self.function_vas[0] < 1 << 64):
            raise InputError("F0 requires exactly one function VA")
        if type(self.expected_image_base) is not int or not 0 <= self.expected_image_base < 1 << 64:
            raise InputError("Invalid expected image base")
        if type(self.allow_partial) is not bool:
            raise InputError("allow_partial must be a JSON boolean")

    @classmethod
    def from_file(cls, path: str | Path) -> ProjectSpec:
        """Decode the exact F0 JSON shape, resolving relative paths at the file."""

        source = Path(path).resolve(strict=True)
        document = json.loads(
            source.read_text(encoding="utf-8-sig"), object_pairs_hook=_unique_pairs,
        )
        expected = {"project_schema_version", "binary_path", "binary_sha256",
                    "frontend", "function_vas", "expected_image_base", "allow_partial"}
        if type(document) is not dict or set(document) != expected:
            raise InputError("Project JSON must contain exactly the F0 fields")
        raw_path = document["binary_path"]
        if type(raw_path) is not str or not raw_path:
            raise InputError("binary_path must be a nonempty string")
        binary_path = Path(raw_path)
        if not binary_path.is_absolute():
            binary_path = source.parent / binary_path
        selection = document["function_vas"]
        if type(selection) is not list or len(selection) != 1:
            raise InputError("function_vas must contain exactly one VA")
        return cls(
            binary_path.resolve(), document["binary_sha256"], document["frontend"],
            (_hex_address(selection[0], "function VA"),),
            _hex_address(document["expected_image_base"], "expected image base"),
            document["allow_partial"], document["project_schema_version"],
        )


@dataclass(frozen=True)
class ResolvedInputs:
    """Exact source bytes and typed conversion facts bound to a ProjectSpec."""

    spec: ProjectSpec
    binary_id: BinaryId
    binary_bytes: bytes
    elf_class: int
    encoding: int
    elf_type: int
    machine: int
    image_base: int
    segments: tuple[Segment, ...]
    selected_va: int
    physical_va: int
    function_rva: int
    instruction_mode: str


def resolve(spec: ProjectSpec) -> ResolvedInputs:
    """Validate the binary digest, ELF mapping and selected code address."""

    if type(spec) is not ProjectSpec:
        raise InputError("Expected ProjectSpec")
    data = spec.binary_path.read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    if digest != spec.binary_sha256:
        raise InputError("Project binary SHA-256 mismatch")
    image = ELFImage(data, load_base=spec.expected_image_base)
    if image.machine not in SUPPORTED_MACHINES:
        raise InputError("ELF machine has no validated frontend mapping")
    if image.image_base != spec.expected_image_base:
        raise InputError("ELF image base differs from Project expectation")
    selected_va = spec.function_vas[0]
    thumb = image.machine == 40 and bool(selected_va & 1)
    physical_va = selected_va & ~1 if thumb else selected_va
    if image.machine == 40 and not thumb and physical_va % 4:
        raise InputError("ARM function VA must be word-aligned or carry the Thumb bit")
    image.read(physical_va, 2 if thumb else 4 if image.machine == 40 else 1)
    return ResolvedInputs(
        spec, BinaryId(digest), data, image.elf_class, image.encoding,
        image.elf_type, image.machine, image.image_base, tuple(image.segments),
        selected_va, physical_va, physical_va - image.image_base,
        "thumb" if thumb else "default",
    )
