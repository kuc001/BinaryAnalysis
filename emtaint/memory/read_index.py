"""List-compatible indexing of existing immutable ``ReadMemory`` records.

No read or guard is merged. Every normal list mutation rebuilds the secondary
index when needed, including same-length edits used by conformance checks.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable, Sequence

from emtaint.core.contracts import SymbolicExprId
from emtaint.memory.state import ReadMemory


class ReadIndex(list[ReadMemory]):
    """Mutable read list with membership and result-expression indexes."""

    def __init__(self, values: Iterable[ReadMemory] = ()) -> None:
        super().__init__(values)
        self._rebuild()

    def _rebuild(self) -> None:
        """Recreate both indexes after an arbitrary list mutation."""

        self._members = Counter(self)
        self._by_result: dict[SymbolicExprId, list[ReadMemory]] = {}
        for read in self:
            self._by_result.setdefault(read.result, []).append(read)

    def __contains__(self, read: object) -> bool:
        try:
            return read in self._members
        except TypeError:
            return False

    def for_result(self, reference: SymbolicExprId) -> tuple[ReadMemory, ...]:
        """Return reads that produced one SSE expression reference."""

        return tuple(self._by_result.get(reference, ()))

    def append(self, read: ReadMemory) -> None:
        """Append one read and update both secondary indexes incrementally."""

        super().append(read)
        self._members[read] += 1
        self._by_result.setdefault(read.result, []).append(read)

    def extend(self, values: Iterable[ReadMemory]) -> None:
        """Append each read while handling extension from this same list."""

        for value in tuple(values) if values is self else values:
            self.append(value)

    def __setitem__(self, key: object, value: object) -> None:
        super().__setitem__(key, value)
        self._rebuild()

    def __delitem__(self, key: object) -> None:
        super().__delitem__(key)
        self._rebuild()

    def insert(self, index: int, value: ReadMemory) -> None:
        """Insert one read at ``index`` and rebuild order-dependent indexes."""

        super().insert(index, value)
        self._rebuild()

    def pop(self, index: int = -1) -> ReadMemory:
        """Remove and return one read, then rebuild secondary indexes."""

        result = super().pop(index)
        self._rebuild()
        return result

    def remove(self, value: ReadMemory) -> None:
        """Remove the first matching read and rebuild secondary indexes."""

        super().remove(value)
        self._rebuild()

    def clear(self) -> None:
        """Remove all reads and clear both secondary indexes."""

        super().clear()
        self._rebuild()

    def reverse(self) -> None:
        """Reverse read order and rebuild order-dependent indexes."""

        super().reverse()
        self._rebuild()

    def sort(self, *args: object, **kwargs: object) -> None:
        """Sort reads using list-compatible arguments and rebuild indexes."""

        super().sort(*args, **kwargs)
        self._rebuild()

    def __iadd__(self, values: Iterable[ReadMemory]) -> "ReadIndex":
        self.extend(values)
        return self

    def __imul__(self, count: int) -> "ReadIndex":
        super().__imul__(count)
        self._rebuild()
        return self


def records_for(
    reads: Sequence[ReadMemory],
    reference: SymbolicExprId,
) -> tuple[ReadMemory, ...]:
    """Return records for one result from indexed or ordinary sequences."""

    if isinstance(reads, ReadIndex):
        return reads.for_result(reference)
    return tuple(read for read in reads if read.result == reference)
