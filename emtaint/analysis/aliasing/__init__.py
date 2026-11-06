"""Demand-driven pointer alias queries over native CIR and shared memory facts."""

from .demand import AliasProcedureDemand
from .program import NativeAliasProgram
from .query import (
    AliasQueryResult, classify_alias_operands, classify_alias_values,
    query_alias,
)

__all__ = [
    "AliasProcedureDemand",
    "NativeAliasProgram",
    "AliasQueryResult",
    "classify_alias_operands",
    "classify_alias_values",
    "query_alias",
]
