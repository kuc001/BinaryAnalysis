"""Immutable input inventory for the source-annotated alias benchmark suites."""

from __future__ import annotations

from collections import Counter
import hashlib
from pathlib import Path

from capstone import CS_ARCH_X86, CS_MODE_32, CS_MODE_64, CS_OP_IMM, Cs
from elftools.elf.elffile import ELFFile

from emtaint.analysis.aliasing.benchmark import MARKERS, parse_alias_expectations


SUITES = (
    "basic_c_tests",
    "basic_cpp_tests",
    "cs_tests",
    "fs_tests",
)

EXPECTED_SOURCE_COUNTS = {
    "basic_c_tests": 56,
    "basic_cpp_tests": 56,
    "cs_tests": 35,
    "fs_tests": 25,
}

EXPECTED_MARKER_COUNTS = {
    "MUSTALIAS": 202,
    "MAYALIAS": 67,
    "NOALIAS": 221,
    "PARTIALALIAS": 0,
    "EXPECTEDFAIL_MAYALIAS": 5,
    "EXPECTEDFAIL_NOALIAS": 4,
}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _relative(path: Path, workspace: Path) -> str:
    return path.resolve().relative_to(workspace.resolve()).as_posix()


def _sources(directory: Path) -> tuple[Path, ...]:
    extensions = {".c", ".cc", ".cpp", ".cxx"}
    return tuple(sorted(
        (path for path in directory.iterdir()
         if path.is_file() and path.suffix.lower() in extensions),
        key=lambda path: path.name,
    ))


def _marker_name(symbol: str) -> str | None:
    """Return the source marker represented by a C or Itanium symbol."""

    for marker in MARKERS:
        if symbol == marker or symbol.startswith("_Z" + str(len(marker)) + marker):
            return marker
    return None


def _direct_marker_calls(path: Path) -> Counter[str]:
    """Count statically preserved direct marker calls in an x86 ELF image.

    The benchmark cannot observe pointer operands when a compiler has removed
    the marker call.  This is an input-coherence check only: call operands and
    source expressions are never returned to the analyzer.
    """

    with path.open("rb") as stream:
        elf = ELFFile(stream)
        if elf.get_machine_arch() not in ("x86", "x64"):
            raise ValueError(
                "Alias-suite marker inventory supports only x86 ELF: " + str(path)
            )
        symbols = elf.get_section_by_name(".symtab")
        if symbols is None:
            raise ValueError("Alias-suite binary has no symbol table: " + str(path))
        targets = {
            int(symbol["st_value"]): marker
            for symbol in symbols.iter_symbols()
            if (marker := _marker_name(symbol.name)) is not None
        }
        disassembler = Cs(
            CS_ARCH_X86,
            CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32,
        )
        disassembler.detail = True
        disassembler.skipdata = True
        calls: Counter[str] = Counter()
        for section in elf.iter_sections():
            if not int(section["sh_flags"]) & 0x4:
                continue
            for instruction in disassembler.disasm(
                    section.data(), int(section["sh_addr"])):
                if (
                        instruction.mnemonic.startswith("call")
                        and instruction.operands
                        and instruction.operands[0].type == CS_OP_IMM):
                    marker = targets.get(int(instruction.operands[0].imm))
                    if marker is not None:
                        calls[marker] += 1
        return calls


def _select_binary(
        workspace: Path, suite: str, source: Path,
        expected: Counter[str]) -> tuple[Path, str, Counter[str], bool]:
    """Select the fixed image with the best preserved marker inventory.

    Some upstream suites ship only an older binary whose marker kinds differ
    from the checked-in source.  Keep the historical primary on an equal
    score, expose the mismatch in the manifest, and prefer a fallback only
    when it demonstrably preserves more of the current source observations.
    """

    primary = workspace / "Test-Suite-master" / "Binaries" / suite / (
        source.name + ".elf"
    )
    fallback = workspace / "Test-Suite-master" / "test_cases_bc" / suite / (
        source.name + ".elf"
    )
    candidates = (
        (primary, "Binaries"),
        (fallback, "test_cases_bc"),
    )
    checked = []
    for binary, origin in candidates:
        if not binary.is_file():
            continue
        calls = _direct_marker_calls(binary)
        score = sum(min(calls[marker], count) for marker, count in expected.items())
        complete = all(
            calls[marker] >= count for marker, count in expected.items()
        )
        checked.append((score, binary, origin, calls, complete))
    if not checked:
        raise FileNotFoundError(
            "No immutable benchmark binary for " + suite + "/" + source.name
        )
    _, binary, origin, calls, complete = max(checked, key=lambda item: item[0])
    return binary, origin, calls, complete


def build_alias_suite_manifest(workspace: Path) -> dict[str, object]:
    """Return a stable manifest after validating the declared suite inventory."""

    workspace = workspace.resolve()
    root = workspace / "Test-Suite-master"
    samples = []
    source_counts: Counter[str] = Counter()
    marker_counts: Counter[str] = Counter()
    smoke_only = 0
    for suite in SUITES:
        for source in _sources(root / suite):
            source_counts[suite] += 1
            expectations = parse_alias_expectations(source)
            counts = Counter(item.marker for item in expectations)
            binary, origin, marker_calls, marker_inventory_complete = _select_binary(
                workspace, suite, source, counts
            )
            if binary.read_bytes()[:4] != b"\x7fELF":
                raise ValueError("Benchmark binary is not ELF: " + str(binary))
            marker_counts.update(counts)
            if not expectations:
                smoke_only += 1
            samples.append({
                "suite": suite,
                "sample": source.name,
                "source": _relative(source, workspace),
                "source_sha256": _sha256(source),
                "binary": _relative(binary, workspace),
                "binary_sha256": _sha256(binary),
                "binary_origin": origin,
                "binary_marker_calls": {
                    marker: marker_calls[marker] for marker in MARKERS
                },
                "binary_marker_inventory_complete": marker_inventory_complete,
                "markers": {marker: counts[marker] for marker in MARKERS},
                "smoke_only": not expectations,
            })
    if dict(source_counts) != EXPECTED_SOURCE_COUNTS:
        raise ValueError(
            "Alias suite source inventory changed: " + repr(dict(source_counts))
        )
    actual_markers = {
        marker: marker_counts[marker]
        for marker in EXPECTED_MARKER_COUNTS
    }
    if actual_markers != EXPECTED_MARKER_COUNTS:
        raise ValueError(
            "Alias suite marker inventory changed: " + repr(actual_markers)
        )
    if smoke_only != 6:
        raise ValueError("Expected exactly 6 smoke-only alias samples")
    return {
        "schema": "emtaint-alias-suite-manifest-v1",
        "workspace_relative": True,
        "suites": list(SUITES),
        "source_counts": dict(source_counts),
        "marker_counts": actual_markers,
        "required_marker_count": sum(
            actual_markers[marker]
            for marker in ("MUSTALIAS", "MAYALIAS", "NOALIAS")
        ),
        "xfail_marker_count": sum(
            actual_markers[marker]
            for marker in (
                "EXPECTEDFAIL_MAYALIAS",
                "EXPECTEDFAIL_NOALIAS",
            )
        ),
        "smoke_only_count": smoke_only,
        "samples": samples,
    }
