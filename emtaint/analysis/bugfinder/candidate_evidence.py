"""Stable references from weak candidates to their source requirement rows."""

from emtaint.analysis.taint.demand_models import (
    SinkRequirement,
    TaintDependency,
)


CANDIDATE_REFS_FORMAT='P7-candidate-refs-v2'


def candidate_key(sink: SinkRequirement, dependency: TaintDependency,
                  offset: int | None) -> tuple:
    """Keep function and exact procedure identity in the candidate key."""
    return (sink.function, sink.site, sink.name, sink.kind, offset, dependency.value)


def requirement_references(requirements: tuple[SinkRequirement, ...],
                           keys: set[tuple]) -> dict[tuple, tuple[tuple[int, int], ...]]:
    """Index all may-flow alternatives without copying their evidence blobs.

    A reference is ``(requirement index, dependency index)`` in the encoded
    requirements file. It includes alternatives not approved by the legacy
    heuristic; each still needs its own feasibility and policy review.
    """
    references: dict[tuple, list[tuple[int, int]]] = {key: [] for key in keys}
    for requirement_index, sink in enumerate(requirements):
        for dependency_index, dependency in enumerate(sink.dependencies):
            if dependency.kind != 'source':
                continue
            offsets = sink.offsets if sink.kind == 'copy' else (None,)
            for offset in offsets:
                key = candidate_key(sink, dependency, offset)
                if key in references:
                    references[key].append((requirement_index, dependency_index))
    return {key: tuple(rows) for key, rows in references.items()}


def source_fact_references(rows: tuple[dict, ...],
                           dependency: TaintDependency) -> tuple[dict, ...]:
    """Select archived facts on this dependency's represented call chain.

    Imported source facts are recorded at the caller callsite that created
    their MemoryVersion.  Prefer those exact sites over the historical
    source-site bucket.  A path without a projected callsite keeps the full
    bucket and is explicitly marked non-exact by the caller.
    """
    matching=tuple(row for row in rows if row.get('source_site')==dependency.value)
    projected=tuple(site for site in dependency.path if site!=dependency.value)
    exact=tuple(row for row in matching if row.get('program_site') in projected)
    selected=exact or matching
    latest={}
    for row in selected:
        key=row.get('function'), row.get('program_site')
        latest[key]=max(latest.get(key, -1), row.get('round', -1))
    selected=tuple(row for row in selected
        if row.get('round', -1)==latest[row.get('function'), row.get('program_site')])
    fields=('fact_id', 'function', 'round', 'origin', 'program_site', 'receipt', 'archive', 'manifest_sha256')
    return tuple({field:row[field] for field in fields if field in row}
        for row in sorted(selected, key=lambda item:(item.get('program_site', -1), item.get('fact_id', ''))))


def merge_fact_references(existing: tuple[dict, ...],
                          additions: tuple[dict, ...]) -> tuple[dict, ...]:
    """Deduplicate additive fact references without dropping MemoryVersions."""
    rows={tuple(sorted(row.items())):row for row in existing+additions}
    return tuple(rows[key] for key in sorted(rows, key=repr))
