"""Validated dependency policies for bounded single-site iCall analysis."""

from __future__ import annotations


RV130_SHA256 = "334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787"

_RV130_SUMMARY_DEPENDENCIES = (
    0x1EA0C,
    0x1E9AC,
    0x1E8A8,
    0x23DC4,
    0x29590,
    0x2E9B4,
)


def dependency_policy(
    binary_sha256: str,
    caller: int,
    site: int,
) -> tuple[int, ...]:
    """Return the independently validated summary bodies for one query.

    The policy is deliberately keyed by binary identity.  Targets from a
    comparison/golden file are never inputs to dependency selection.
    """

    if binary_sha256 == RV130_SHA256:
        return _RV130_SUMMARY_DEPENDENCIES
    raise ValueError(
        "No validated iCall dependency policy for binary "
        f"{binary_sha256}, caller={hex(caller)}, site={hex(site)}"
    )
