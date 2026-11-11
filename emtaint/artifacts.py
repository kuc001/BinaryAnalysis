"""F0 immutable acquisition publication and verified detached reload."""

from __future__ import annotations

from dataclasses import asdict, dataclass, fields
from enum import Enum
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
from uuid import uuid4

from emtaint.analysis_debugging import InstructionHint, ProvenanceIndex, SourceHint
from emtaint.core import Completeness, FunctionId
from emtaint.core.contracts import CIR_VERSION, MEMORY_VERSION
from emtaint.frontends.inputs import InputError
from emtaint.frontends.saved_cir import decode_saved_cir
from emtaint.graph import ControlFlowGraph, FlowEdge, FlowKind
from emtaint.ir.canonical import CIRModule
from emtaint.ir.canonical.wire import dumps
from emtaint.project import ProjectSpec, ResolvedInputs, SUPPORTED_MACHINES, resolve

MANIFEST_SCHEMA = "AcquisitionManifest-F0-v1"
CFG_SCHEMA = "CFG-Artifact-F0-v1"
ORIGINS_SCHEMA = "Origins-F0-v1"
REPORT_SCHEMA = "FrontendReport-F0-v1"
HINTS_SCHEMA = "ProvenanceHints-F0-v1"
SOURCE_SCHEMA = "SourceSelection-F0-v1"
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024
ARTIFACT_PATHS = {
    "architecture": "architecture.json",
    "producer": "producer.json",
    "assessment": "assessment.json",
    "origins": "origins.json",
    "report": "frontend-report.json",
    "source": "source/function-{rva}.json",
    "cfg": "cfg/function-{rva}.json",
    "cir": "cir/function-{rva}.json",
    "source_hints": "provenance/source-hints.json",
    "instruction_hints": "provenance/instruction-hints.json",
}
ARTIFACT_SCHEMAS = {
    "architecture": CIR_VERSION,
    "producer": CIR_VERSION,
    "assessment": CIR_VERSION,
    "origins": ORIGINS_SCHEMA,
    "report": REPORT_SCHEMA,
    "source": SOURCE_SCHEMA,
    "cfg": CFG_SCHEMA,
    "cir": CIR_VERSION,
    "source_hints": HINTS_SCHEMA,
    "instruction_hints": HINTS_SCHEMA,
}


class IntegrityStatus(str, Enum):
    """File and reference integrity, independent of semantic completeness."""

    VALID = "valid"
    MISSING = "missing"
    CORRUPT = "corrupt"
    INCOMPATIBLE = "incompatible"
    STALE = "stale"


class SemanticCompleteness(str, Enum):
    """Whether acquired CIR and CFG model the selected function completely."""

    COMPLETE = "complete"
    PARTIAL = "partial"


class ArtifactError(ValueError):
    """An acquisition cannot be loaded or published with the stated status."""

    def __init__(self, status: IntegrityStatus, detail: str) -> None:
        self.status = status
        super().__init__(detail)


@dataclass(frozen=True)
class ArtifactRoot:
    """Explicit directory for immutable F0 generations."""

    path: Path

    def __post_init__(self) -> None:
        if not isinstance(self.path, Path):
            raise TypeError("ArtifactRoot path must be a Path")


@dataclass(frozen=True)
class AcquisitionRef:
    """A generation and externally pinned manifest digest for detached load."""

    generation: Path
    manifest_sha256: str
    schema_version: str = MANIFEST_SCHEMA

    def __post_init__(self) -> None:
        if (not isinstance(self.generation, Path)
                or not self.generation.name.startswith("generation-")):
            raise ValueError("AcquisitionRef requires a published generation path")
        if (type(self.manifest_sha256) is not str
                or re.fullmatch(r"[0-9a-f]{64}", self.manifest_sha256) is None):
            raise ValueError("AcquisitionRef requires a pinned manifest SHA-256")
        if self.schema_version != MANIFEST_SCHEMA:
            raise ValueError("Unsupported AcquisitionRef schema version")


@dataclass(frozen=True)
class FunctionInputs:
    """Verified, frontend-neutral inputs for a later analysis query."""

    module: CIRModule
    cfg: ControlFlowGraph
    provenance: ProvenanceIndex
    report: dict[str, object]
    reference: AcquisitionRef
    artifact_hashes: dict[str, str]
    integrity: IntegrityStatus
    semantic_completeness: SemanticCompleteness
    diagnostics: tuple[str, ...]


def _json_bytes(record: object) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("Duplicate artifact JSON key: " + key)
        result[key] = value
    return result


def _reject_number(value: str) -> object:
    raise ValueError("Artifact JSON contains unsupported number: " + value)


def _json_record(data: bytes) -> object:
    return json.loads(data.decode("utf-8"), object_pairs_hook=_unique_pairs,
                      parse_float=_reject_number, parse_constant=_reject_number)


def _cfg_record(cfg: ControlFlowGraph) -> dict[str, object]:
    return {
        "schema_version": CFG_SCHEMA,
        "function": {"binary_sha256": cfg.function.binary.sha256, "rva": cfg.function.rva},
        "nodes": sorted(node.token for node in cfg.nodes),
        "edges": sorted(({
            "source": edge.source.token, "target": edge.target.token,
            "kind": edge.kind.value, "label": edge.label,
        } for edge in cfg.edges), key=lambda edge: (
            edge["source"], edge["target"], edge["kind"], edge["label"])),
        "entry": None if cfg.entry is None else cfg.entry.token,
        "exits": sorted(node.token for node in cfg.exits),
        "status": cfg.status.value,
        "reason": cfg.reason,
    }


def _payloads(
    inputs: ResolvedInputs,
    module: CIRModule,
    cfg: ControlFlowGraph,
    provenance: ProvenanceIndex,
    report: dict[str, object],
) -> dict[str, bytes]:
    if len(module.functions) != 1 or cfg.function != module.functions[0].function_id:
        raise ValueError("F0 publication requires exactly one matching function and CFG")
    origins = {
        origin.id: {
            "block": origin.point.block.token,
            "statement_index": origin.point.statement,
            "instruction_rva": origin.point.instruction_rva,
            "source_opcode": origin.source_opcode,
        }
        for origin in module.origin_map
    }
    metadata = report.get("metadata")
    source_functions = metadata.get("source_functions") if type(metadata) is dict else None
    if type(source_functions) is not list or len(source_functions) != 1:
        raise ValueError("Frontend report omitted the selected source function")
    source = {
        "schema_version": SOURCE_SCHEMA,
        "function": {"binary_sha256": module.binary_sha256,
                     "rva": module.functions[0].function_id.rva},
        "selected_va": inputs.selected_va,
        "function_input": source_functions[0],
        "block_mappings": report.get("block_mappings"),
        "coverage": report.get("coverage"),
    }
    return {
        "architecture": dumps(module.architecture).encode("utf-8"),
        "producer": dumps(module.producer).encode("utf-8"),
        "assessment": dumps(module.assessment).encode("utf-8"),
        "origins": _json_bytes(origins),
        "report": _json_bytes(report),
        "source": _json_bytes(source),
        "cfg": _json_bytes(_cfg_record(cfg)),
        "cir": dumps(module.functions[0], max_nodes=8_000_000,
                     max_bytes=MAX_ARTIFACT_BYTES).encode("utf-8"),
        "source_hints": _json_bytes({"schema_version": HINTS_SCHEMA,
                                     "hints": [asdict(h) for h in provenance.source_hints]}),
        "instruction_hints": _json_bytes({
            "schema_version": HINTS_SCHEMA,
            "hints": [asdict(h) for h in provenance.instruction_hints],
        }),
    }


def _semantic_status(
    module: CIRModule, cfg: ControlFlowGraph, report: dict[str, object],
) -> SemanticCompleteness:
    coverage = report.get("coverage")
    if (module.assessment.status == Completeness.COMPLETE
            and cfg.status == Completeness.COMPLETE
            and type(coverage) is list
            and all(type(row) is dict and row.get("status") != "unsupported" for row in coverage)):
        return SemanticCompleteness.COMPLETE
    return SemanticCompleteness.PARTIAL


def _manifest(
    inputs: ResolvedInputs,
    module: CIRModule,
    cfg: ControlFlowGraph,
    report: dict[str, object],
    tool_versions: dict[str, str],
    payloads: dict[str, bytes],
    generation_name: str,
) -> dict[str, object]:
    function = module.functions[0].function_id
    rva = f"{function.rva:x}"
    artifacts = {}
    for kind, data in payloads.items():
        artifacts[kind] = {
            "path": ARTIFACT_PATHS[kind].format(rva=rva),
            "schema_version": ARTIFACT_SCHEMAS[kind],
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
    assessment = module.assessment
    return {
        "schema_version": MANIFEST_SCHEMA,
        "generation": generation_name,
        "binary_sha256": inputs.binary_id.sha256,
        "function": {"binary_sha256": function.binary.sha256, "rva": function.rva},
        "address_mapping": {
            "selected_va": inputs.selected_va,
            "physical_va": inputs.physical_va,
            "function_rva": inputs.function_rva,
            "image_base": inputs.image_base,
            "elf_class": inputs.elf_class,
            "encoding": inputs.encoding,
            "elf_type": inputs.elf_type,
            "machine": inputs.machine,
            "instruction_mode": inputs.instruction_mode,
            "segments": [
                {"va": va, "file_offset": offset, "file_size": file_size,
                 "memory_size": memory_size, "flags": flags}
                for va, offset, file_size, memory_size, flags in inputs.segments
            ],
        },
        "producer": asdict(module.producer),
        "versions": {"cir_wire": CIR_VERSION, "memory_semantics": MEMORY_VERSION,
                     "tools": tool_versions},
        "assessment": {
            "status": assessment.status.value,
            "precision": assessment.precision.value,
            "precision_loss": list(assessment.precision_loss),
            "unsupported_ops": list(assessment.unsupported_ops),
            "diagnostics": list(assessment.diagnostics),
            "cfg_status": cfg.status.value,
        },
        "semantic_completeness": _semantic_status(module, cfg, report).value,
        "diagnostics": [*assessment.diagnostics, cfg.reason],
        "artifacts": artifacts,
    }


def _write_bytes(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def _is_link(path: Path) -> bool:
    return path.is_symlink() or (hasattr(path, "is_junction") and path.is_junction())


def _safe_file(generation: Path, relative: object) -> Path:
    if type(relative) is not str or not relative or "\\" in relative or ":" in relative:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid artifact path")
    pure = PurePosixPath(relative)
    if (pure.is_absolute() or str(pure) != relative
            or any(part in (".", "..", "") for part in pure.parts)):
        raise ArtifactError(IntegrityStatus.CORRUPT, "Artifact path escapes generation")
    candidate = generation.joinpath(*pure.parts)
    if _is_link(generation) or any(_is_link(path) for path in (candidate, *candidate.parents)
                                   if path == generation or generation in path.parents):
        raise ArtifactError(IntegrityStatus.CORRUPT, "Artifact path traverses a link")
    if not candidate.resolve().is_relative_to(generation.resolve()):
        raise ArtifactError(IntegrityStatus.CORRUPT, "Artifact path escapes generation")
    return candidate


def _read_checked(generation: Path, relative: object, size: object, sha256: object) -> bytes:
    if type(size) is not int or not 0 <= size <= MAX_ARTIFACT_BYTES:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid artifact size")
    if type(sha256) is not str or re.fullmatch(r"[0-9a-f]{64}", sha256) is None:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid artifact digest")
    path = _safe_file(generation, relative)
    try:
        with path.open("rb") as source:
            data = source.read(size + 1)
    except FileNotFoundError as error:
        raise ArtifactError(
            IntegrityStatus.MISSING, "Missing artifact: " + str(relative),
        ) from error
    if len(data) != size or hashlib.sha256(data).hexdigest() != sha256:
        raise ArtifactError(
            IntegrityStatus.CORRUPT, "Artifact size/hash mismatch: " + str(relative),
        )
    return data


def _load_manifest(generation: Path, pinned_sha256: str, *, staging: bool) -> dict[str, object]:
    if not staging and not generation.name.startswith("generation-"):
        raise ArtifactError(IntegrityStatus.MISSING, "Only published generations can be read")
    if _is_link(generation):
        raise ArtifactError(IntegrityStatus.CORRUPT, "Generation is a link")
    path = generation / "manifest.json"
    if _is_link(path):
        raise ArtifactError(IntegrityStatus.CORRUPT, "Manifest is a link")
    try:
        with path.open("rb") as source:
            data = source.read(MAX_MANIFEST_BYTES + 1)
    except FileNotFoundError as error:
        raise ArtifactError(IntegrityStatus.MISSING, "Missing published manifest") from error
    if len(data) > MAX_MANIFEST_BYTES or hashlib.sha256(data).hexdigest() != pinned_sha256:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Pinned manifest SHA-256 mismatch")
    try:
        manifest = _json_record(data)
    except (ValueError, UnicodeError) as error:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid manifest JSON") from error
    if type(manifest) is not dict:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Manifest must be an object")
    if manifest.get("schema_version") != MANIFEST_SCHEMA:
        raise ArtifactError(IntegrityStatus.INCOMPATIBLE, "Unsupported manifest schema")
    if not staging and manifest.get("generation") != generation.name:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Manifest generation mismatch")
    return manifest


def _checked_artifacts(generation: Path, manifest: dict[str, object]) -> dict[str, bytes]:
    records = manifest.get("artifacts")
    if type(records) is not dict or set(records) != set(ARTIFACT_PATHS):
        raise ArtifactError(IntegrityStatus.CORRUPT, "Manifest artifact table is incomplete")
    payloads: dict[str, bytes] = {}
    paths: set[str] = set()
    function_rva = manifest["function"]["rva"]
    for kind, row in records.items():
        if type(row) is not dict or set(row) != {"path", "schema_version", "size", "sha256"}:
            raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid artifact row: " + kind)
        if row["schema_version"] != ARTIFACT_SCHEMAS[kind]:
            raise ArtifactError(
                IntegrityStatus.INCOMPATIBLE, "Unsupported artifact schema: " + kind,
            )
        relative = row["path"]
        if relative != ARTIFACT_PATHS[kind].format(rva=f"{function_rva:x}"):
            raise ArtifactError(
                IntegrityStatus.CORRUPT, "Artifact layout differs from F0 schema: " + kind,
            )
        if type(relative) is not str:
            raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid artifact path type")
        if relative in paths:
            raise ArtifactError(IntegrityStatus.CORRUPT, "Duplicate artifact path")
        paths.add(relative)
        payloads[kind] = _read_checked(generation, relative, row["size"], row["sha256"])
    return payloads


def _decode_cfg(data: bytes, function: FunctionId, module: CIRModule) -> ControlFlowGraph:
    record = _json_record(data)
    required = {"schema_version", "function", "nodes", "edges", "entry",
                "exits", "status", "reason"}
    if type(record) is not dict or set(record) != required:
        raise ValueError("Invalid CFG artifact shape")
    if record["schema_version"] != CFG_SCHEMA:
        raise ArtifactError(IntegrityStatus.INCOMPATIBLE, "Unsupported CFG schema")
    if record["function"] != {"binary_sha256": function.binary.sha256, "rva": function.rva}:
        raise ValueError("CFG function identity mismatch")
    blocks = {block.id.token: block.id for block in module.functions[0].blocks}
    nodes = record["nodes"]
    exits = record["exits"]
    edges = record["edges"]
    if (type(nodes) is not list or type(exits) is not list or type(edges) is not list
            or len(nodes) != len(set(nodes)) or len(exits) != len(set(exits))
            or set(nodes) != set(blocks) or not set(exits) <= set(blocks)):
        raise ValueError("CFG node/exit references differ from CIR")
    expected_entry = None if module.functions[0].entry is None else module.functions[0].entry.token
    if record["entry"] != expected_entry:
        raise ValueError("CFG entry differs from CIR")
    parsed_edges = []
    for edge in edges:
        if type(edge) is not dict or set(edge) != {"source", "target", "kind", "label"}:
            raise ValueError("Invalid CFG edge shape")
        parsed_edges.append(FlowEdge(blocks[edge["source"]], blocks[edge["target"]],
                                     FlowKind(edge["kind"]), edge["label"]))
    if len(set(parsed_edges)) != len(parsed_edges):
        raise ValueError("Duplicate CFG edge")
    return ControlFlowGraph(
        function, frozenset(blocks.values()), frozenset(parsed_edges),
        None if record["entry"] is None else blocks[record["entry"]],
        frozenset(blocks[token] for token in exits),
        Completeness(record["status"]), record["reason"],
    )


def _decode_hints(data: bytes, record_type: type[SourceHint] | type[InstructionHint]) -> tuple:
    record = _json_record(data)
    if type(record) is not dict or set(record) != {"schema_version", "hints"}:
        raise ValueError("Invalid provenance sidecar shape")
    if record["schema_version"] != HINTS_SCHEMA:
        raise ArtifactError(IntegrityStatus.INCOMPATIBLE, "Unsupported provenance schema")
    if type(record["hints"]) is not list:
        raise ValueError("Provenance hints must be a list")
    expected = {field.name for field in fields(record_type)}
    hints = []
    for row in record["hints"]:
        if type(row) is not dict or set(row) != expected:
            raise ValueError("Invalid provenance hint fields")
        for field in fields(record_type):
            value = row[field.name]
            if field.name in {"function_rva", "block_rva", "statement_index",
                              "instruction_rva", "vex_temporary", "register_offset"}:
                if value is not None and type(value) is not int:
                    raise ValueError("Invalid provenance address/index type")
            elif value is not None and type(value) is not str:
                raise ValueError("Invalid provenance text type")
        hints.append(record_type(**row))
    return tuple(hints)


def _validate_provenance(module: CIRModule, provenance: ProvenanceIndex) -> None:
    origins = {origin.id: origin for origin in module.origin_map}
    values = {value.id for value in module.functions[0].values}
    for hint in provenance.source_hints:
        if hint.origin_id not in origins or hint.value_id not in values:
            raise ValueError("Source hint has an unknown value/origin")
    for hint in provenance.instruction_hints:
        origin = origins.get(hint.origin_id)
        if (origin is None or hint.function_rva != origin.point.function.rva
                or hint.block_rva != origin.point.block.rva
                or hint.instruction_rva != origin.point.instruction_rva
                or hint.source_opcode != origin.source_opcode):
            raise ValueError("Instruction hint differs from its Origin")


def _validate_report(report: object, module: CIRModule, cfg: ControlFlowGraph,
                     mapping: dict[str, object]) -> dict[str, object]:
    if type(report) is not dict:
        raise ValueError("Frontend report must be an object")
    if (report.get("binary_sha256") != module.binary_sha256
            or report.get("producer") != module.producer.frontend
            or report.get("functions") != 1
            or report.get("cir_blocks") != len(module.functions[0].blocks)
            or report.get("status") != module.assessment.status.value):
        raise ValueError("Frontend report identity/status mismatch")
    metadata = report.get("metadata")
    if type(metadata) is not dict or metadata.get("image_base") != mapping["image_base"]:
        raise ValueError("Frontend report image base mismatch")
    rows = report.get("cfgs")
    if type(rows) is not list or len(rows) != 1:
        raise ValueError("Frontend report CFG row missing")
    expected = {
        "function_rva": cfg.function.rva,
        "nodes": sorted(node.token for node in cfg.nodes),
        "edges": sorted((edge.source.token, edge.target.token, edge.kind.value, edge.label)
                        for edge in cfg.edges),
        "status": cfg.status.value,
    }
    row = rows[0]
    if type(row) is not dict or set(row) != set(expected):
        raise ValueError("Frontend report CFG shape mismatch")
    if {**expected, "edges": [list(edge) for edge in expected["edges"]]} != row:
        raise ValueError("Frontend report CFG differs from artifact")
    coverage = report.get("coverage")
    origins = {origin.id for origin in module.origin_map}
    if type(coverage) is not list or any(type(item) is not dict or item.get("origin") not in origins
                                         for item in coverage):
        raise ValueError("Frontend coverage has dangling Origin")
    return report


def _validate_source(source: object, report: dict[str, object],
                     module: CIRModule, mapping: dict[str, object]) -> None:
    if type(source) is not dict or set(source) != {
        "schema_version", "function", "selected_va", "function_input",
        "block_mappings", "coverage",
    }:
        raise ValueError("Invalid source selection artifact shape")
    if source["schema_version"] != SOURCE_SCHEMA:
        raise ArtifactError(IntegrityStatus.INCOMPATIBLE, "Unsupported source schema")
    function = module.functions[0].function_id
    metadata = report["metadata"]
    if (source["function"] != {"binary_sha256": function.binary.sha256, "rva": function.rva}
            or source["selected_va"] != mapping["selected_va"]
            or source["function_input"] != metadata["source_functions"][0]
            or source["block_mappings"] != report["block_mappings"]
            or source["coverage"] != report["coverage"]
            or source["function_input"]["address"] != mapping["physical_va"]):
        raise ValueError("Source selection differs from report, CIR or address mapping")
    blocks = {block.id.token for block in module.functions[0].blocks}
    for row in source["block_mappings"]:
        if type(row) is not dict or not set(row.get("cir_blocks", ())) <= blocks:
            raise ValueError("Source mapping contains an undeclared CIR block")


def _validated_generation(
    generation: Path,
    pinned_sha256: str,
    function: FunctionId,
    *,
    staging: bool = False,
) -> FunctionInputs:
    manifest = _load_manifest(generation, pinned_sha256, staging=staging)
    expected_fields = {"schema_version", "generation", "binary_sha256", "function",
                       "address_mapping", "producer", "versions", "assessment",
                       "semantic_completeness", "diagnostics", "artifacts"}
    if set(manifest) != expected_fields:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Manifest fields differ from F0 schema")
    if (manifest["binary_sha256"] != function.binary.sha256
            or manifest["function"] != {"binary_sha256": function.binary.sha256,
                                        "rva": function.rva}):
        raise ArtifactError(IntegrityStatus.STALE, "Requested function differs from manifest")
    mapping = manifest["address_mapping"]
    mapping_fields = {
        "selected_va", "physical_va", "function_rva", "image_base", "elf_class",
        "encoding", "elf_type", "machine", "instruction_mode", "segments",
    }
    if type(mapping) is not dict or set(mapping) != mapping_fields:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid address mapping")
    if (any(type(mapping[key]) is not int for key in ("selected_va", "physical_va",
        "function_rva", "image_base", "elf_class", "encoding", "elf_type", "machine"))
            or mapping["function_rva"] != function.rva
            or mapping["elf_class"] not in (1, 2)
            or mapping["encoding"] not in (1, 2)
            or mapping["elf_type"] not in (2, 3)
            or mapping["machine"] not in SUPPORTED_MACHINES
            or mapping["physical_va"] - mapping["image_base"] != function.rva
            or mapping["selected_va"] != mapping["physical_va"] + (
                1 if mapping["instruction_mode"] == "thumb" else 0
            )
            or (mapping["instruction_mode"] == "thumb") != (
                mapping["machine"] == 40 and bool(mapping["selected_va"] & 1)
            )
            or type(mapping["segments"]) is not list or not mapping["segments"]):
        raise ArtifactError(IntegrityStatus.CORRUPT, "Inconsistent VA/RVA/mode mapping")
    for segment in mapping["segments"]:
        if (type(segment) is not dict
                or set(segment) != {"va", "file_offset", "file_size", "memory_size", "flags"}
                or any(type(value) is not int or value < 0 for value in segment.values())
                or segment["file_size"] > segment["memory_size"]):
            raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid ELF segment mapping")
    if not any(segment["va"] <= mapping["physical_va"] < segment["va"] + segment["file_size"]
               and segment["flags"] & 1 for segment in mapping["segments"]):
        raise ArtifactError(
            IntegrityStatus.CORRUPT, "Selected function has no executable file mapping",
        )
    versions = manifest["versions"]
    if (type(versions) is not dict or set(versions) != {"cir_wire", "memory_semantics", "tools"}
            or versions["cir_wire"] != CIR_VERSION or versions["memory_semantics"] != MEMORY_VERSION
            or type(versions["tools"]) is not dict
            or set(versions["tools"]) != {"angr", "pyvex", "archinfo", "cle", "claripy"}
            or any(value != "9.3.4" for value in versions["tools"].values())):
        raise ArtifactError(
            IntegrityStatus.INCOMPATIBLE, "Unsupported acquisition producer versions",
        )
    payloads = _checked_artifacts(generation, manifest)
    for kind in ("origins", "report", "source", "cfg", "source_hints", "instruction_hints"):
        _json_record(payloads[kind])  # Reject duplicate keys before the existing CIR decoder.
    module, report, body_hashes = decode_saved_cir(
        (payloads["cir"],), payloads["architecture"], payloads["producer"],
        payloads["assessment"], payloads["origins"], payloads["report"],
    )
    if len(module.functions) != 1 or module.functions[0].function_id != function:
        raise ValueError("CIR body identity differs from pinned manifest")
    if module.producer.frontend != "angr-vex" or asdict(module.producer) != manifest["producer"]:
        raise ValueError("CIR producer differs from manifest")
    assessment = module.assessment
    expected_assessment = {
        "status": assessment.status.value, "precision": assessment.precision.value,
        "precision_loss": list(assessment.precision_loss),
        "unsupported_ops": list(assessment.unsupported_ops),
        "diagnostics": list(assessment.diagnostics),
    }
    if type(manifest["assessment"]) is not dict or any(
        manifest["assessment"].get(key) != value for key, value in expected_assessment.items()
    ) or set(manifest["assessment"]) != set(expected_assessment) | {"cfg_status"}:
        raise ValueError("Manifest assessment differs from CIR")
    cfg = _decode_cfg(payloads["cfg"], function, module)
    if manifest["assessment"]["cfg_status"] != cfg.status.value:
        raise ValueError("Manifest CFG status differs from artifact")
    source_hints = _decode_hints(payloads["source_hints"], SourceHint)
    instruction_hints = _decode_hints(payloads["instruction_hints"], InstructionHint)
    provenance = ProvenanceIndex(module, source_hints, instruction_hints)
    _validate_provenance(module, provenance)
    report = _validate_report(report, module, cfg, mapping)
    _validate_source(_json_record(payloads["source"]), report, module, mapping)
    semantic = _semantic_status(module, cfg, report)
    if manifest["semantic_completeness"] != semantic.value:
        raise ValueError("Manifest semantic completeness is overstated")
    diagnostics = (*assessment.diagnostics, cfg.reason)
    if manifest["diagnostics"] != list(diagnostics):
        raise ValueError("Manifest diagnostics differ from saved semantics")
    if body_hashes[function] != manifest["artifacts"]["cir"]["sha256"]:
        raise ValueError("CIR body hash differs after decoding")
    reference_path = generation.parent / manifest["generation"] if staging else generation
    reference = AcquisitionRef(reference_path, pinned_sha256)
    return FunctionInputs(
        module, cfg, provenance, report, reference,
        {kind: row["sha256"] for kind, row in manifest["artifacts"].items()},
        IntegrityStatus.VALID, semantic, diagnostics,
    )


def load(
    reference: AcquisitionRef,
    function: FunctionId,
    *,
    project: ProjectSpec | None = None,
) -> FunctionInputs:
    """Verify a pinned generation without native lifting or the source binary.

    Supplying ``project`` opts into a current-source comparison; a detached
    load has no such dependency and never calls angr.
    """

    if type(reference) is not AcquisitionRef or type(function) is not FunctionId:
        raise TypeError("load requires AcquisitionRef and FunctionId")
    try:
        loaded = _validated_generation(reference.generation, reference.manifest_sha256, function)
    except ArtifactError:
        raise
    except (OSError, ValueError, TypeError, KeyError, UnicodeError) as error:
        raise ArtifactError(
            IntegrityStatus.CORRUPT, "Invalid saved acquisition: " + str(error),
        ) from error
    if project is not None:
        try:
            current = resolve(project)
        except (OSError, InputError) as error:
            raise ArtifactError(
                IntegrityStatus.STALE, "Current Project cannot be verified: " + str(error),
            ) from error
        manifest = _load_manifest(reference.generation, reference.manifest_sha256, staging=False)
        mapping = manifest["address_mapping"]
        if (current.binary_id != function.binary or current.function_rva != function.rva
                or current.selected_va != mapping["selected_va"]
                or current.physical_va != mapping["physical_va"]
                or current.instruction_mode != mapping["instruction_mode"]
                or current.image_base != mapping["image_base"]
                or [
                    {"va": va, "file_offset": offset, "file_size": file_size,
                     "memory_size": memory_size, "flags": flags}
                    for va, offset, file_size, memory_size, flags in current.segments
                ] != mapping["segments"]):
            raise ArtifactError(IntegrityStatus.STALE, "Current Project differs from acquisition")
    return loaded


def publish(
    inputs: ResolvedInputs,
    module: CIRModule,
    cfg: ControlFlowGraph,
    provenance: ProvenanceIndex,
    report: dict[str, object],
    tool_versions: dict[str, str],
    root: ArtifactRoot,
) -> AcquisitionRef:
    """Write, verify and atomically publish one immutable F0 generation."""

    if len(module.functions) != 1:
        raise ValueError("F0 publication requires exactly one CIR function")
    if module.binary_sha256 != inputs.binary_id.sha256:
        raise ValueError("Frontend binary differs from resolved Project")
    if module.functions[0].function_id.rva != inputs.function_rva:
        raise ValueError("Frontend function RVA differs from selected VA")
    semantic = _semantic_status(module, cfg, report)
    if semantic == SemanticCompleteness.PARTIAL and not inputs.spec.allow_partial:
        raise InputError("Project forbids a semantically partial acquisition")
    payloads = _payloads(inputs, module, cfg, provenance, report)
    generation_name = "generation-" + uuid4().hex
    manifest = _manifest(inputs, module, cfg, report, tool_versions, payloads, generation_name)
    manifest_bytes = _json_bytes(manifest)
    if len(manifest_bytes) > MAX_MANIFEST_BYTES:
        raise ValueError("F0 manifest exceeds byte budget")
    root.path.mkdir(parents=True, exist_ok=True)
    if _is_link(root.path):
        raise ValueError("Artifact root cannot be a link")
    staging = Path(tempfile.mkdtemp(prefix=".staging-f0-", dir=root.path))
    published = False
    try:
        for kind, data in payloads.items():
            _write_bytes(staging / manifest["artifacts"][kind]["path"], data)
        _write_bytes(staging / "manifest.json", manifest_bytes)
        digest = hashlib.sha256(manifest_bytes).hexdigest()
        _validated_generation(staging, digest, module.functions[0].function_id, staging=True)
        generation = root.path / generation_name
        if generation.exists():
            raise FileExistsError("Acquisition generation already exists")
        staging.rename(generation)
        published = True
        return AcquisitionRef(generation, digest)
    finally:
        if not published and staging.exists() and staging.parent == root.path:
            shutil.rmtree(staging)
