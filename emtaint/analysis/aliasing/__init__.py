"""Pointer-alias benchmark analysis over native CIR and LegacyDemand."""

from .benchmark import (
    AliasBenchmarkReport,
    AliasExpectation,
    AliasObservation,
    analyze_alias_benchmark,
    parse_alias_expectations,
)

__all__ = [
    "AliasBenchmarkReport",
    "AliasExpectation",
    "AliasObservation",
    "analyze_alias_benchmark",
    "parse_alias_expectations",
]
