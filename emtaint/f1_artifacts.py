"""F1 manifest codec backed by the shared immutable generation operations."""
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from uuid import uuid4

from emtaint.analysis_debugging import representation_provenance as provenance_wire
from emtaint.artifacts import (
    ArtifactError, IntegrityStatus, SemanticCompleteness, _load_manifest,
    _publish_generation, _read_checked,
)
from emtaint.core.identity import BinaryId, FunctionId
from emtaint.core.wire_json import canonical_json, digest_text, fields, read_record
from emtaint.f1_evidence import SCHEMA as EVIDENCE_SCHEMA, build_provenance, inventories, validate_evidence
from emtaint.frontends import ctree_source
from emtaint.graph.program_graphs import ControlFlowGraph
from emtaint.ir.canonical import wire_v2
from emtaint.ir.canonical.hir_lowering import Lowering
from emtaint.ir.hir import model as hir_wire

MANIFEST = "AcquisitionManifest-F1-v1"
ARTIFACTS = {
    "source": ("source/ctree.json", ctree_source.SCHEMA),
    "hir": ("hir/function.json", hir_wire.SCHEMA),
    "cir": ("cir/function.json", wire_v2.SCHEMA),
    "cfg": ("cfg/function.json", wire_v2.CFG_SCHEMA),
    "evidence": ("provenance/instructions.json", EVIDENCE_SCHEMA),
    "provenance": ("provenance/relations.json", provenance_wire.SCHEMA),
}


@dataclass(frozen=True)
class F1Reference:
    """Published generation and caller-held manifest SHA-256."""
    generation: Path
    manifest_sha256: str

    def __post_init__(self) -> None:
        if not isinstance(self.generation, Path) or not self.generation.name.startswith("generation-"):
            raise ValueError("F1 reference requires a published generation path")
        digest_text(self.manifest_sha256)


@dataclass(frozen=True)
class F1Inputs:
    """Detached F1 analysis inputs and their already-computed evidence."""
    hir: hir_wire.HIRFunction
    cir: wire_v2.CIRFunctionV2
    cfg: ControlFlowGraph
    provenance: provenance_wire.ProvenanceGraph
    evidence: dict
    manifest: dict
    integrity: IntegrityStatus = IntegrityStatus.VALID

    @property
    def semantic_completeness(self) -> SemanticCompleteness:
        return (SemanticCompleteness.COMPLETE if self.cir.completeness == "complete"
                else SemanticCompleteness.PARTIAL)


def _pin(data: bytes) -> str:
    return sha256(data).hexdigest()


def _namespaces(payloads: dict[str, bytes]) -> dict[str, str]:
    cir = _pin(payloads["cir"])
    return {
        "source": _pin(payloads["source"]), "hir": _pin(payloads["hir"]),
        "block": cir, "effect": cir, "definition": cir, "use": cir,
        "instruction": _pin(payloads["evidence"]),
    }


def _mapping(project: ctree_source.VerifiedProject, source: ctree_source.ValidatedCTree) -> dict:
    return {
        "source_domain": "IDA_EA", "linked_domain": "LINKED_VA", "mode": "arm",
        "image_base": project.image_base, "entry_ea": source.document["function"]["entry_ea"],
        "end_ea": source.document["function"]["end_ea"], "segments": [list(row) for row in project.segments],
    }


def _project(manifest: dict) -> ctree_source.VerifiedProject:
    identity, mapping = manifest["function"], manifest["address_mapping"]
    fields(identity, {"binary_sha256", "rva"})
    fields(mapping, {"source_domain", "linked_domain", "mode", "image_base",
                     "entry_ea", "end_ea", "segments"})
    binary = BinaryId(identity["binary_sha256"])
    function = FunctionId(binary, identity["rva"])
    segments = mapping["segments"]
    if (mapping["source_domain"], mapping["linked_domain"], mapping["mode"]) != ("IDA_EA", "LINKED_VA", "arm"):
        raise ValueError("Unsupported F1 address mapping")
    if type(segments) is not list or not segments:
        raise ValueError("Missing ELF segments")
    for segment in segments:
        if (type(segment) is not list or len(segment) != 5
                or any(type(value) is not int or not 0 <= value < 1 << 64 for value in segment)
                or segment[2] > segment[3]):
            raise ValueError("Invalid ELF segment")
    base = mapping["image_base"]
    if type(base) is not int or base != min(segment[0] for segment in segments):
        raise ValueError("Invalid F1 image base")
    return ctree_source.VerifiedProject(function, base, tuple(tuple(segment) for segment in segments))


def _artifacts(generation: Path, manifest: dict) -> dict[str, bytes]:
    descriptors = manifest["artifacts"]
    fields(descriptors, set(ARTIFACTS))
    payloads = {}
    for kind, (path, schema) in ARTIFACTS.items():
        descriptor = descriptors[kind]
        fields(descriptor, {"path", "schema_version", "sha256", "size"})
        if descriptor["schema_version"] != schema:
            raise ArtifactError(IntegrityStatus.INCOMPATIBLE, f"Unsupported F1 artifact schema: {kind}")
        if descriptor["path"] != path:
            raise ArtifactError(IntegrityStatus.CORRUPT, f"Invalid F1 artifact path: {kind}")
        payloads[kind] = _read_checked(generation, path, descriptor["size"], descriptor["sha256"])
    return payloads


def _validate_links(source: ctree_source.ValidatedCTree, hir: hir_wire.HIRFunction,
                    cir: wire_v2.CIRFunctionV2, evidence: dict, provenance: provenance_wire.ProvenanceGraph) -> None:
    source_nodes = source.document["nodes"]
    if {node["source_id"] for node in hir.nodes.values()} != set(source_nodes):
        raise ValueError("HIR source node inventory differs from CTree")
    if {row["source_id"] for row in hir.types.values()} != set(source.document["types"]):
        raise ValueError("HIR source type inventory differs from CTree")
    if {row["index"] for row in hir.variables.values()} != set(range(len(source.document["local_variables"]))):
        raise ValueError("HIR source variable inventory differs from CTree")
    for record in hir.types.values():
        if record["facts"] != source.document["types"][record["source_id"]]:
            raise ValueError("HIR type evidence differs from source")
    for record in hir.variables.values():
        original = source.document["local_variables"][record["index"]]
        if (any(record[key] != original[key] for key in ("name", "size_bytes", "storage", "user_type", "user_name"))
                or (record["role"] == "parameter") != original["argument"]
                or hir.types.get(record["type_id"], {}).get("source_id") != original["type_id"]):
            raise ValueError("HIR variable evidence differs from source")
    for key, node in hir.nodes.items():
        row = source_nodes[node["source_id"]]
        projected = [{**child, "id": hir.nodes[child["id"]]["source_id"]} for child in node["children"]]
        address = node["address"]
        if projected != (row["children"] or []) or address != (
                {"domain": "IDA_EA", "value": row["ea"]} if row["ea"] is not None else None):
            raise ValueError("HIR source order or address differs from CTree")
        if not any(edge["relation"] == "normalizes_to" and edge["source"] == ["source", node["source_id"]]
                   for edge in provenance.related("hir", key)):
            raise ValueError("Missing HIR source provenance")
    for definition in cir.definitions.values():
        if definition["variable"] is not None and definition["variable"] not in hir.variables:
            raise ValueError("CIR definition refers to an unknown variable")
    for block in cir.blocks.values():
        for effect in block["effects"]:
            related = provenance.related("effect", effect["id"])
            if (not effect["provenance"] or any(node not in hir.nodes or not any(
                    edge["source"] == ["hir", node] and edge["relation"] == "lowers_to" for edge in related)
                    for node in effect["provenance"])):
                raise ValueError("Invalid CIR-to-HIR reference")
            instruction = effect["instruction_origin"]
            if instruction is not None and (instruction not in evidence["instructions"] or not any(
                    edge["target"] == ["instruction", instruction] for edge in related)):
                raise ValueError("Invalid CIR-to-instruction reference")
            allowed = {machine for node in effect["provenance"]
                       for machine in evidence["witnesses"].get(hir.nodes[node]["source_id"], {}).get("instructions", ())}
            if any(edge["target"][0] == "instruction" and edge["target"][1] not in allowed for edge in related):
                raise ValueError("CIR-to-instruction edge lacks a saved correspondence witness")


def _load(path: Path, pin: str, *, staging: bool) -> F1Inputs:
    manifest = _load_manifest(path, pin, staging=staging, schema=MANIFEST)
    fields(manifest, {"schema_version", "generation", "function", "address_mapping", "source_fingerprint",
                      "producer", "semantic_completeness", "diagnostics", "artifacts"})
    payloads = _artifacts(path, manifest)
    project = _project(manifest)
    source = ctree_source.read_ctree(
        payloads["source"], project,
        ctree_source.ExpectedExport(manifest["artifacts"]["source"]["sha256"], manifest["source_fingerprint"]),
    )
    if manifest["address_mapping"] != _mapping(project, source):
        raise ValueError("Manifest address mapping disagrees with source")
    hir_record, cir_record = read_record(payloads["hir"]), read_record(payloads["cir"])
    if hir_record.get("schema_version") != hir_wire.SCHEMA or cir_record.get("schema_version") != wire_v2.SCHEMA:
        raise ArtifactError(IntegrityStatus.INCOMPATIBLE, "Unsupported saved HIR or CIR version")
    hir = hir_wire.decode_hir(payloads["hir"], project.function)
    cir = wire_v2.decode_cir(payloads["cir"], project.function)
    if (hir.source_sha256 != source.expected.sha256 or hir.export_fingerprint != source.expected.fingerprint
            or manifest["producer"] != _producer(source, hir, cir)
            or manifest["semantic_completeness"] != cir.completeness or manifest["diagnostics"] != cir.diagnostics):
        raise ValueError("Manifest source, producer or assessment mismatch")
    if read_record(payloads["cfg"]) != wire_v2.cfg_record(cir):
        raise ValueError("Saved CFG disagrees with CIR")
    evidence = read_record(payloads["evidence"])
    validate_evidence(evidence, source)
    provenance = provenance_wire.ProvenanceGraph.from_record(
        read_record(payloads["provenance"]), project.function.token,
        _namespaces(payloads), inventories(hir, cir, evidence),
    )
    _validate_links(source, hir, cir, evidence, provenance)
    return F1Inputs(hir, cir, wire_v2.graph(cir), provenance, evidence, manifest)


def load_f1(reference: F1Reference, *, current_export: ctree_source.ExpectedExport | None = None,
            current_binary: BinaryId | None = None) -> F1Inputs:
    """Read saved data only. Optional caller-supplied pins detect stale inputs."""
    try:
        inputs = _load(reference.generation, reference.manifest_sha256, staging=False)
    except ArtifactError:
        raise
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError, RecursionError) as error:
        raise ArtifactError(IntegrityStatus.CORRUPT, "Invalid saved F1 acquisition: " + str(error)) from error
    if (current_export is not None and current_export != ctree_source.ExpectedExport(
            inputs.hir.source_sha256, inputs.hir.export_fingerprint)
            or current_binary is not None and current_binary != inputs.cir.function.binary):
        raise ArtifactError(IntegrityStatus.STALE, "Current input pins differ from saved acquisition")
    return inputs


def _producer(source: ctree_source.ValidatedCTree, hir: hir_wire.HIRFunction,
              cir: wire_v2.CIRFunctionV2) -> dict:
    return {"frontend_capability": ctree_source.CAPABILITY,
            "ida": source.document["environment"]["ida_version"],
            "hexrays": source.document["environment"]["hexrays_version"],
            "python": source.document["environment"]["python_version"],
            "normalizer": hir.normalizer, "lowerer": cir.producer}


def publish_f1(root: Path, source_bytes: bytes, source: ctree_source.ValidatedCTree,
               hir: hir_wire.HIRFunction, lowered: Lowering, evidence: dict) -> F1Reference:
    """Publish one verified immutable F1 generation using shared storage."""
    cir = lowered.cir
    payloads = {
        "source": source_bytes, "hir": hir_wire.encode_hir(hir), "cir": wire_v2.encode_cir(cir),
        "cfg": canonical_json(wire_v2.cfg_record(cir)), "evidence": canonical_json(evidence),
    }
    provenance = build_provenance(hir, lowered, evidence, _namespaces(payloads))
    payloads["provenance"] = canonical_json(provenance.to_record())
    name = "generation-" + uuid4().hex
    manifest = {
        "schema_version": MANIFEST, "generation": name,
        "function": {"binary_sha256": cir.function.binary.sha256, "rva": cir.function.rva},
        "address_mapping": _mapping(source.project, source), "source_fingerprint": hir.export_fingerprint,
        "producer": _producer(source, hir, cir), "semantic_completeness": cir.completeness,
        "diagnostics": cir.diagnostics,
        "artifacts": {kind: {"path": path, "schema_version": schema,
                             "size": len(payloads[kind]), "sha256": _pin(payloads[kind])}
                      for kind, (path, schema) in ARTIFACTS.items()},
    }
    generation, pin = _publish_generation(
        root, name, manifest, payloads, lambda path, pin: _load(path, pin, staging=True),
        staging_prefix=".staging-f1-",
    )
    return F1Reference(generation, pin)
