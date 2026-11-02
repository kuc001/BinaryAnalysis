"""Session-local reverse dependencies for P7 hash-table source summaries."""
from __future__ import annotations

from collections import defaultdict
from typing import Hashable, Iterable

from .tables import TableRoot


class TableReadIndex:
    """Replace a function's observed table reads after each reanalysis.

    Missing or unknown roots use the old key-insensitive fallback and therefore
    depend on every table update. Exact roots depend only on their own bank row.
    """

    def __init__(self)->None:
        self.by_function:dict[Hashable, tuple[frozenset[TableRoot], frozenset[TableRoot]]]={}
        self.by_root:dict[TableRoot, set[Hashable]]=defaultdict(set)
        self.broad:set[Hashable]=set()

    def replace(self, function:Hashable, roots:Iterable[TableRoot], broad:Iterable[TableRoot])->None:
        current=frozenset(roots), frozenset(broad)
        if not current[1]<=current[0]:raise ValueError('Broad table reads must also be recorded as reads')
        previous=self.by_function.get(function)
        if previous is not None:
            for root in previous[0]:
                readers=self.by_root[root]
                readers.discard(function)
                if not readers:del self.by_root[root]
            self.broad.discard(function)
        self.by_function[function]=current
        for root in current[0]:self.by_root[root].add(function)
        if current[1]:self.broad.add(function)

    def affected(self, root:TableRoot)->frozenset[Hashable]:
        return frozenset(set(self.by_root.get(root, ()))|self.broad)
