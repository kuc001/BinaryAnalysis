"""Finite may-path automata with explicit repeated-word widening.

The inclusion argument is syntactic: ``prefix.word^k.suffix`` is contained in
``prefix.word*.suffix`` for every non-negative ``k``. No heap identities or
aliases are inferred. Uncompressible paths exhaust explicitly; they are never
silently truncated.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence

from emtaint.core import Completeness
from emtaint.core.contracts import AccessGraphId, Assessment, Precision
from emtaint.debugging import EventSampler
from emtaint.memory.access_path import (
    APGEdge,
    APGNode,
    APGSummary,
    AccessGraph,
    AccessPath,
)
from emtaint.memory.policies import Accounting


LOGGER = logging.getLogger(__name__)
MEMBERSHIP_EVENTS = EventSampler(LOGGER, first=10, every=1_000)


class AccessGraphArena:
    """Intern function-scoped access paths as bounded finite automata.

    Args:
        scope: Function/context/session scope shared by every APG identity.
        budgets: Semantic limits used for node, edge and summary accounting.
        graphs: Optional mutable graph store already owned by the memory engine.
    """

    def __init__(
        self,
        scope: object,
        budgets: object,
        *,
        graphs: Mapping[AccessGraphId, AccessGraph] | None = None,
    ) -> None:
        self.scope = scope
        self.accounting = Accounting(budgets)
        self.graphs = {} if graphs is None else graphs
        self._intern: dict[object, AccessGraphId] = {}
        self._events = EventSampler(LOGGER, first=10, every=1_000)
        for dimension, attribute in (
            ("apg_nodes", "nodes"),
            ("apg_edges", "edges"),
            ("apg_summaries", "summaries"),
        ):
            self.accounting.set(
                dimension,
                sum(
                    len(getattr(graph, attribute))
                    for graph in self.graphs.values()
                ),
            )
        self._events.emit(
            "apg.arena.initialized",
            function=hex(scope.function.rva),
            context=str(scope.context),
            existing_graphs=len(self.graphs),
        )

    def next_id(self) -> AccessGraphId:
        """Return the first unused deterministic APG identity in this scope."""

        index = len(self.graphs)
        while AccessGraphId(self.scope, "apg-" + str(index)) in self.graphs:
            index += 1
        return AccessGraphId(self.scope, "apg-" + str(index))

    def field_closure(
        self,
        root: object,
        patterns: Iterable[Sequence[object]],
        trigger: str,
    ) -> AccessGraph:
        """Build language ``(field_1 | ... | field_n)*`` over field words.

        Every finite sequence over the exact supplied words is accepted,
        including left/right tree and next/previous walks. This proves language
        inclusion only; it says nothing about heap cycles, CFGs or contexts.
        """

        patterns = tuple(dict.fromkeys(tuple(pattern) for pattern in patterns))
        if not patterns or any(not pattern for pattern in patterns):
            raise ValueError("Nonempty field words required")
        key = (root, patterns, trigger, "closure")
        if key in self._intern:
            graph = self.graphs[self._intern[key]]
            self._events.emit(
                "apg.field_closure.cache_hit",
                graph=graph.id.key,
                patterns=len(patterns),
                trigger=trigger,
            )
            return graph
        self.accounting.check(
            "apg_nodes",
            self.accounting.counts["apg_nodes"] + 1,
        )
        self.accounting.check(
            "apg_summaries",
            self.accounting.counts["apg_summaries"] + len(patterns),
        )
        summaries = tuple(
            APGSummary(
                "n0",
                "n0",
                pattern,
                0,
                None,
                trigger,
                "Explicit recursive-field alphabet closure",
                "Each finite field-word sequence is a concatenation of zero "
                "or more supplied words",
                "All field combinations/depths retained; infeasible "
                "combinations admitted",
                Completeness.COMPLETE,
            )
            for pattern in patterns
        )
        graph = AccessGraph(
            self.next_id(),
            (APGNode("n0", root),),
            (),
            summaries,
            ("n0",),
            ("n0",),
            Assessment(
                Completeness.COMPLETE,
                Precision.OVER_APPROX,
                (
                    "Recursive-field alphabet closed under arbitrary finite "
                    "repetition",
                ),
                diagnostics=(),
            ),
        )
        self.accounting.charge("apg_nodes")
        self.accounting.charge("apg_summaries", len(patterns))
        self.graphs[graph.id] = graph
        self._intern[key] = graph.id
        self._events.emit(
            "apg.field_closure.created",
            graph=graph.id.key,
            patterns=len(patterns),
            summaries=len(summaries),
            trigger=trigger,
        )
        return graph

    def intern(self, path: AccessPath, trigger: str) -> AccessGraph:
        """Intern one access path, widening three or more repeated field words."""

        key = (path.root, path.segments, trigger)
        if key in self._intern:
            graph = self.graphs[self._intern[key]]
            self._events.emit(
                "apg.path.cache_hit",
                graph=graph.id.key,
                path=path.id.key,
                segments=len(path.segments),
                trigger=trigger,
            )
            return graph
        segments = path.segments
        nodes = [APGNode("n0", path.root)]
        edges = []
        summaries = []
        current = "n0"
        index = 0
        while index < len(segments):
            repeated = None
            maximum_word = min(16, (len(segments) - index) // 3)
            for size in range(1, maximum_word + 1):
                pattern = segments[index : index + size]
                repetitions = 1
                while (
                    segments[
                        index + repetitions * size :
                        index + (repetitions + 1) * size
                    ]
                    == pattern
                ):
                    repetitions += 1
                if repetitions >= 3:
                    repeated = (pattern, repetitions)
                    break
            if repeated:
                pattern, repetitions = repeated
                summaries.append(
                    APGSummary(
                        current,
                        current,
                        pattern,
                        0,
                        None,
                        trigger,
                        "Contiguous repeated field word widened",
                        f"prefix.word^{repetitions}.suffix subset "
                        f"prefix.word*.suffix (word length {len(pattern)})",
                        "Repetition count forgotten; additional paths may be "
                        "accepted",
                        Completeness.COMPLETE,
                    )
                )
                index += len(pattern) * repetitions
            else:
                target = "n" + str(len(nodes))
                nodes.append(APGNode(target))
                edges.append(APGEdge(current, target, segments[index]))
                current = target
                index += 1
            for dimension, count in (
                ("apg_nodes", len(nodes)),
                ("apg_edges", len(edges)),
                ("apg_summaries", len(summaries)),
            ):
                self.accounting.check(
                    dimension,
                    self.accounting.counts[dimension] + count,
                )
        assessment = (
            Assessment(
                Completeness.COMPLETE,
                Precision.OVER_APPROX,
                ("Repeated field-word count widened to Kleene star",),
                diagnostics=(),
            )
            if summaries
            else Assessment.complete()
        )
        graph = AccessGraph(
            self.next_id(),
            tuple(nodes),
            tuple(edges),
            tuple(summaries),
            ("n0",),
            (current,),
            assessment,
        )
        for dimension, count in (
            ("apg_nodes", len(nodes)),
            ("apg_edges", len(edges)),
            ("apg_summaries", len(summaries)),
        ):
            self.accounting.charge(dimension, count)
        self.graphs[graph.id] = graph
        self._intern[key] = graph.id
        self._events.emit(
            "apg.path.created",
            graph=graph.id.key,
            path=path.id.key,
            input_segments=len(segments),
            nodes=len(nodes),
            edges=len(edges),
            summaries=len(summaries),
            widened=bool(summaries),
            trigger=trigger,
        )
        return graph


def accepts(
    graph: AccessGraph,
    segments: Sequence[object],
    max_steps: int = 100_000,
) -> bool:
    """Test NFA membership for ordinary and finite-word summary transitions."""

    todo = [(entry, 0) for entry in graph.entries]
    seen = set()
    steps = 0
    MEMBERSHIP_EVENTS.emit(
        "apg.membership.started",
        graph=graph.id.key,
        segments=len(segments),
        max_steps=max_steps,
    )
    while todo:
        node, position = todo.pop()
        if (node, position) in seen:
            continue
        seen.add((node, position))
        steps += 1
        if steps > max_steps:
            MEMBERSHIP_EVENTS.emit(
                "apg.membership.exhausted",
                level=logging.WARNING,
                graph=graph.id.key,
                segments=len(segments),
                steps=steps,
                max_steps=max_steps,
            )
            raise RuntimeError("APG membership incomplete: query-step budget")
        if position == len(segments) and node in graph.accepting:
            MEMBERSHIP_EVENTS.emit(
                "apg.membership.completed",
                graph=graph.id.key,
                accepted=True,
                steps=steps,
                visited=len(seen),
            )
            return True
        for edge in graph.edges:
            if (
                edge.source == node
                and position < len(segments)
                and segments[position] == edge.label
            ):
                todo.append((edge.target, position + 1))
        for summary in graph.summaries:
            if summary.source != node:
                continue
            size = len(summary.pattern)
            repetitions = 0
            end = position
            while True:
                if repetitions >= summary.minimum_repetitions:
                    todo.append((summary.target, end))
                if (
                    summary.maximum_repetitions is not None
                    and repetitions >= summary.maximum_repetitions
                ):
                    break
                if segments[end : end + size] != summary.pattern:
                    break
                end += size
                repetitions += 1
    MEMBERSHIP_EVENTS.emit(
        "apg.membership.completed",
        graph=graph.id.key,
        accepted=False,
        steps=steps,
        visited=len(seen),
    )
    return False
