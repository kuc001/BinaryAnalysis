"""Versioned bidirectional provenance for persisted representation artifacts."""
from dataclasses import dataclass
from functools import cached_property

from emtaint.core.wire_json import fields

SCHEMA = "Representation-Provenance-v1"
KINDS = {"source", "hir", "block", "effect", "definition", "use", "instruction"}
MAPPINGS = {"mapped", "partial", "ambiguous", "unavailable"}
COVERAGE = {"lowered", "partial", "unsupported", "no_effect"}
RELATIONS = {"normalizes_to", "derives", "lowers_to", "corresponds_to"}
CONFIDENCE = {"BINARY_CONFIRMED", "DECOMPILER_RECOVERED", "ANALYSIS_DERIVED", "UNKNOWN"}


@dataclass(frozen=True)
class ProvenanceGraph:
    """Persisted relations with independently scoped artifact namespaces."""
    function: str
    namespaces: dict[str, str]
    edges: tuple[dict, ...]
    coverage: dict[str, dict]
    conflicts: tuple[dict, ...]

    def related(self, kind: str, local_id: str) -> tuple[dict, ...]:
        """Return saved edges in either direction without making an analysis query."""
        return self._incident.get((kind, local_id), ())

    @cached_property
    def _incident(self) -> dict[tuple[str, str], tuple[dict, ...]]:
        index: dict[tuple[str, str], list[dict]] = {}
        for edge in self.edges:
            for key in dict.fromkeys((tuple(edge["source"]), tuple(edge["target"]))):
                index.setdefault(key, []).append(edge)
        return {key: tuple(edges) for key, edges in index.items()}

    def to_record(self) -> dict:
        return {"schema_version": SCHEMA, "function": self.function, "namespaces": self.namespaces,
                "edges": list(self.edges), "coverage": self.coverage, "conflicts": list(self.conflicts)}

    @classmethod
    def from_record(cls, record: dict, function: str, namespaces: dict[str, str],
                    inventories: dict[str, set[str]]) -> "ProvenanceGraph":
        """Validate every saved reference against decoded artifact inventories."""
        fields(record, {"schema_version", "function", "namespaces", "edges", "coverage", "conflicts"})
        if (record["schema_version"] != SCHEMA or record["function"] != function
                or record["namespaces"] != namespaces or set(inventories) != KINDS):
            raise ValueError("Incompatible provenance scope")

        def endpoint(value: object) -> None:
            if (type(value) is not list or len(value) != 2 or value[0] not in inventories
                    or value[1] not in inventories[value[0]]):
                raise ValueError("Dangling provenance endpoint")

        if type(record["edges"]) is not list or type(record["conflicts"]) is not list:
            raise ValueError("Invalid provenance collections")
        seen = set()
        normalized = set()
        lowered = set()
        for edge in record["edges"]:
            fields(edge, {"source", "target", "relation", "status", "confidence", "method", "reason"})
            endpoint(edge["source"])
            endpoint(edge["target"])
            if (edge["relation"] not in RELATIONS or edge["status"] not in MAPPINGS
                    or edge["confidence"] not in CONFIDENCE
                    or any(type(edge[key]) is not str or not edge[key] for key in ("method", "reason"))):
                raise ValueError("Invalid provenance relation")
            key = (tuple(edge["source"]), tuple(edge["target"]), edge["relation"], edge["method"])
            if key in seen:
                raise ValueError("Duplicate provenance relation")
            seen.add(key)
            if edge["relation"] == "normalizes_to":
                if edge["source"][0] != "source" or edge["target"][0] != "hir":
                    raise ValueError("Invalid normalization edge")
                normalized.add(edge["source"][1])
            if edge["relation"] == "lowers_to" and edge["target"][0] == "effect":
                lowered.add(edge["source"][1])
        coverage = record["coverage"]
        if type(coverage) is not dict or set(coverage) != inventories["hir"] or normalized != inventories["source"]:
            raise ValueError("Missing HIR coverage or source mapping")
        for node, row in coverage.items():
            fields(row, {"lowering", "instruction_mapping", "reason"})
            if (row["lowering"] not in COVERAGE or row["instruction_mapping"] not in MAPPINGS
                    or not row["reason"] or (row["lowering"] == "no_effect" and node in lowered)):
                raise ValueError("Invalid HIR coverage")
        seen_conflicts = set()
        for conflict in record["conflicts"]:
            fields(conflict, {"id", "property", "facts", "status", "reason"})
            if (conflict["id"] in seen_conflicts or conflict["status"] != "unresolved"
                    or type(conflict["facts"]) is not list or len(conflict["facts"]) < 2
                    or any(type(conflict[key]) is not str or not conflict[key] for key in ("id", "property", "reason"))):
                raise ValueError("Invalid provenance conflict")
            seen_conflicts.add(conflict["id"])
            for fact in conflict["facts"]:
                endpoint(fact)
        return cls(function, namespaces, tuple(record["edges"]), coverage, tuple(record["conflicts"]))
