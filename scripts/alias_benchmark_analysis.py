"""Test-only source expectations and reports for the native alias query API."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import re

from emtaint.analysis.aliasing.program import NativeAliasProgram


MARKERS = (
    "NOALIAS",
    "MAYALIAS",
    "MUSTALIAS",
    "PARTIALALIAS",
    "EXPECTEDFAIL_MAYALIAS",
    "EXPECTEDFAIL_NOALIAS",
)
_MARKER_PATTERN = re.compile(
    r"\b(" + "|".join(MARKERS) + r")\s*\(\s*([^,]+?)\s*,\s*([^)]+?)\s*\)"
)

_EXPECTED_KIND = {
    "EXPECTEDFAIL_MAYALIAS": "MAYALIAS",
    "EXPECTEDFAIL_NOALIAS": "NOALIAS",
}


def matches_expectation(expected: str, predicted: str, complete: bool) -> bool:
    """A proved MUST relation refines an asserted MAY relation."""

    return complete and (
        expected == predicted
        or (expected == "MAYALIAS" and predicted == "MUSTALIAS")
    )


@dataclass(frozen=True)
class AliasExpectation:
    """One active source marker and its human-readable operands."""

    kind: str
    line: int
    left: str
    right: str
    status: str = "required"
    marker: str | None = None

    def __post_init__(self) -> None:
        marker = self.kind if self.marker is None else self.marker
        if marker not in MARKERS:
            raise ValueError("Unsupported alias expectation marker " + marker)
        if self.status not in ("required", "xfail"):
            raise ValueError("Unsupported alias expectation status " + self.status)
        object.__setattr__(self, "marker", marker)


@dataclass(frozen=True)
class AliasObservation:
    """One independently computed binary alias result."""

    function: str
    site: int
    marker: str
    predicted: str
    expected: str | None
    source_line: int | None
    left: str | None
    right: str | None
    alias_kinds: tuple[str, ...]
    evidence: tuple[str, ...]
    complete: bool
    reason_codes: tuple[str, ...] = ()
    expected_status: str = "required"

    @property
    def matched(self) -> bool | None:
        """Return expectation agreement, or None without a source marker."""

        return (
            None
            if self.expected is None
            else matches_expectation(
                self.expected, self.predicted, self.complete
            )
        )


@dataclass(frozen=True)
class AliasBenchmarkReport:
    """Identity, coverage, and observations for one source/binary pair."""

    source: str
    binary: str
    binary_sha256: str
    image_base: int
    functions: tuple[str, ...]
    expectations: tuple[AliasExpectation, ...]
    observations: tuple[AliasObservation, ...]
    diagnostics: tuple[str, ...] = ()

    @property
    def matched(self) -> int:
        return sum(
            item.expected_status == "required" and item.matched is True
            for item in self.observations
        )

    @property
    def total(self) -> int:
        return sum(item.status == "required" for item in self.expectations)

    @property
    def xfailed(self) -> int:
        """Return expected-failure checks that still disagree or are incomplete."""

        return sum(
            item.expected_status == "xfail" and item.matched is False
            for item in self.observations
        )

    @property
    def xpassed(self) -> int:
        """Return expected-failure checks now satisfied by the analyzer."""

        return sum(
            item.expected_status == "xfail" and item.matched is True
            for item in self.observations
        )

    def as_dict(self) -> dict[str, object]:
        """Return a stable JSON-ready representation."""

        return {
            "source": self.source,
            "binary": self.binary,
            "binary_sha256": self.binary_sha256,
            "image_base": self.image_base,
            "functions": list(self.functions),
            "expectations": [vars(item) for item in self.expectations],
            "observations": [
                {
                    **vars(item),
                    "matched": item.matched,
                    "alias_kinds": list(item.alias_kinds),
                    "evidence": list(item.evidence),
                }
                for item in self.observations
            ],
            "matched": self.matched,
            "total": self.total,
            "xfailed": self.xfailed,
            "xpassed": self.xpassed,
            "diagnostics": list(self.diagnostics),
        }



def _without_comments(text: str) -> str:
    """Blank C/C++ comments while preserving character and line positions."""

    def blank(match: re.Match[str]) -> str:
        return "".join("\n" if char == "\n" else " " for char in match.group())

    return re.sub(r"//[^\n]*|/\*.*?\*/", blank, text, flags=re.DOTALL)


def parse_alias_expectations(path: str | os.PathLike[str]) -> tuple[AliasExpectation, ...]:
    """Parse active alias markers without accepting commented-out checks."""

    text = Path(path).read_text(encoding="utf-8", errors="replace")
    clean = _without_comments(text)
    result = []
    for match in _MARKER_PATTERN.finditer(clean):
        marker = match.group(1)
        result.append(
            AliasExpectation(
                _EXPECTED_KIND.get(marker, marker),
                clean.count("\n", 0, match.start()) + 1,
                match.group(2).strip(),
                match.group(3).strip(),
                "xfail" if marker.startswith("EXPECTEDFAIL_") else "required",
                marker,
            )
        )
    return tuple(result)

class _BenchmarkAnalyzer(NativeAliasProgram):
    def __init__(self, source: Path, binary: Path) -> None:
        self.source = source
        self.expectations = parse_alias_expectations(source)
        super().__init__(binary, MARKERS)

    def run(self) -> AliasBenchmarkReport:
        raw = self.query_calls()
        expected_by_kind = {
            marker: [item for item in self.expectations if item.marker == marker]
            for marker in MARKERS
        }
        expected_indexes = {marker: 0 for marker in MARKERS}
        observations = []
        for function, site, marker, predicted, kinds, evidence, complete, reasons in raw:
            index = expected_indexes[marker]
            candidates = expected_by_kind[marker]
            expected = candidates[index] if index < len(candidates) else None
            expected_indexes[marker] += 1
            observations.append(AliasObservation(
                function, site, marker, predicted,
                expected.kind if expected else None,
                expected.line if expected else None,
                expected.left if expected else None,
                expected.right if expected else None,
                kinds, evidence, complete, reasons,
                expected.status if expected else "required",
            ))
        missing = len(self.expectations) - len(observations)
        if missing:
            self.diagnostics.append(
                str(missing) + " source marker(s) were not matched to binary calls"
            )
        module = next(iter(self.lifted.values())).function
        ordered = sorted(
            self.lifted.values(), key=lambda item: item.function.function_id.rva
        )
        return AliasBenchmarkReport(
            str(self.source.resolve()), str(self.binary.resolve()),
            module.function_id.binary.sha256, self.base,
            tuple(item.name for item in ordered), self.expectations,
            tuple(observations), tuple(self.diagnostics),
        )


def analyze_alias_benchmark(
        source: str | os.PathLike[str],
        binary: str | os.PathLike[str]) -> AliasBenchmarkReport:
    """Analyze one source/binary benchmark pair and return all marker results."""

    source_path = Path(source).resolve()
    binary_path = Path(binary).resolve()
    if not source_path.is_file() or not binary_path.is_file():
        raise FileNotFoundError("Alias benchmark source and binary must exist")
    return _BenchmarkAnalyzer(source_path, binary_path).run()
