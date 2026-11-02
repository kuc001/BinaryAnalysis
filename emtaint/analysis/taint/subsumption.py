"""Antichains of existing may-source alternatives in the legacy bound domain.

For one Source/region/lineage, numeric Cons values denote an upper copy-length
bound (the original policy takes their minimum, excluding sentinel 0/1).
An absent bound is unconstrained. Extra guards or length recipes can only
restrict an alternative. Hence an existing larger/absent bound with subsets
of these conditions covers the narrower alternative under caller binding.

Keep the covering input verbatim: no merged witness, new source, guard, path,
memory identity, or constraint is manufactured. Symbolic policy tags, handle
lineage, offsets, widths, uncertainty and unresolved status remain separate.
Formal/global dependencies are intentionally outside this rule. This is
redundancy elimination in the private P7 domain, not an SMT feasibility proof.
"""
from dataclasses import replace


def source_antichain(dependencies, on_covered=None):
    groups={}
    result=[]
    for dependency in dependencies:
        if dependency.kind!='source':
            result.append(dependency)
            continue
        numbers=[value for value in dependency.constraints if type(value) is int and value not in (0, 1)]
        tags=frozenset((type(value), value) for value in dependency.constraints if type(value) is not int or value in (0, 1))
        key=(replace(dependency, constraints=(), path=(), guards=(), recipes=()), tags)
        groups.setdefault(key, []).append((dependency, min(numbers) if numbers else None,
            frozenset(dependency.guards), frozenset(dependency.recipes)))

    def covers(broad, narrow):
        return ((broad[1] is None or (narrow[1] is not None and broad[1]>=narrow[1]))
            and broad[2]<=narrow[2] and broad[3]<=narrow[3])

    for alternatives in groups.values():
        kept=[]
        for row in alternatives:
            covering=next((previous for previous in kept if covers(previous, row)), None)
            if covering is not None:
                if on_covered:on_covered(row[0], covering[0])
                continue
            if on_covered:
                for previous in kept:
                    if covers(row, previous):on_covered(previous[0], row[0])
            kept=[previous for previous in kept if not covers(row, previous)]
            kept.append(row)
        result.extend(row[0] for row in kept)
    return tuple(result)
