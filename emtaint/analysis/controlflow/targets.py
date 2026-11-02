"""Commit may/confirmed CIR target evidence without importing Golden facts."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
import logging

from emtaint.analysis.framework.runtime import AnalysisRuntime
from emtaint.analysis.framework.state import TargetFact
from emtaint.core import FunctionId
from emtaint.core.contracts import Origin
from emtaint.debugging import log_event
from emtaint.graph import CallEdge, FlowEdge, FlowKind, TargetKind


LOGGER = logging.getLogger(__name__)


class TargetGraphUpdater:
    """Translate computed targets into versioned call/control-flow graph facts."""

    def __init__(
        self,
        runtime: AnalysisRuntime,
        origins: Sequence[Origin],
    ) -> None:
        """Bind the updater to one analysis session and CIR origin map.

        Args:
            runtime: Owner of the current CFG, CG, epochs, and invalidation set.
            origins: CIR source records used to map switch facts back to blocks.
        """

        self.runtime = runtime
        self.origins = {origin.id: origin for origin in origins}
        self.unmapped: list[tuple[str, int, str]] = []

    def apply(self, facts: Iterable[TargetFact]) -> frozenset[FunctionId]:
        """Apply one batch of target evidence and return invalidated functions.

        Args:
            facts: iCall, direct-call, or switch target facts from CIR analysis.

        Returns:
            Functions whose scoped results became stale after CFG/CG updates.
        """

        facts = tuple(facts)
        session = self.runtime.session
        program = session.program
        call_edges = set()
        cfgs = {}
        affected: set[FunctionId] = set()
        sites = set()
        unmapped_before = len(self.unmapped)
        log_event(
            LOGGER,
            "graph.targets.apply.started",
            facts=len(facts),
            cg_edges_before=len(session.cg.edges),
        )

        for fact in facts:
            if fact.kind in ("icall", "direct"):
                sites.add(fact.site)
                for value in fact.targets:
                    try:
                        target = program.function_at(value)
                    except ValueError:
                        target = None
                    if target is None:
                        self.unmapped.append(
                            (fact.origin, value, "Undeclared callee")
                        )
                        log_event(
                            LOGGER,
                            "graph.target.unmapped",
                            level=logging.WARNING,
                            origin=fact.origin,
                            target=hex(value),
                            kind=fact.kind,
                        )
                        continue
                    certainty = (
                        TargetKind.CONFIRMED
                        if fact.certainty == "confirmed"
                        else TargetKind.MAY
                    )
                    call_edges.add(
                        CallEdge(
                            fact.site,
                            target.id,
                            certainty,
                            self.runtime.INFERRED_PREFIX + fact.evidence,
                        )
                    )
            elif fact.kind == "switch":
                origin = self.origins[fact.origin]
                source = origin.point.block
                cfg = cfgs.get(source.function, session.cfg(source.function))
                for value in fact.targets:
                    matches = [
                        block
                        for block in cfg.nodes
                        if program.absolute_address(block.rva)
                        == (value & ~1 if block.mode == "thumb" else value)
                    ]
                    if not matches:
                        self.unmapped.append(
                            (fact.origin, value, "Undeclared switch block")
                        )
                    for target in matches:
                        cfg = cfg.with_edge(
                            FlowEdge(
                                source,
                                target,
                                FlowKind.SWITCH,
                                "P6 abstract computed-target candidate",
                            )
                        )
                cfgs[source.function] = cfg

        if sites:
            affected.update(
                self.runtime.replace_inferred_call_edges(sites, call_edges)
            )
        for cfg in cfgs.values():
            affected.update(self.runtime.replace_cfg(cfg))

        log_event(
            LOGGER,
            "graph.targets.apply.completed",
            facts=len(facts),
            callsites=len(sites),
            inferred_call_edges=len(call_edges),
            updated_cfgs=len(cfgs),
            affected=len(affected),
            cg_edges_after=len(session.cg.edges),
            unmapped_added=len(self.unmapped) - unmapped_before,
        )
        return frozenset(affected)
