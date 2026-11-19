"""Application entry point for pinned CTree acquisition."""
from dataclasses import dataclass
from pathlib import Path

from emtaint.core.identity import BinaryId
from emtaint.core.wire_json import fields, hex_address, read_record
from emtaint.f1_artifacts import F1Reference, publish_f1
from emtaint.f1_evidence import capture_evidence
from emtaint.frontends.ctree_source import ExpectedExport, VerifiedProject, build_hir, read_ctree
from emtaint.frontends.inputs import ELFImage
from emtaint.ir.canonical.hir_lowering import lower_hir
from emtaint.ir.hir.model import decode_hir, encode_hir

SCHEMA = "ProjectSpec-F1-v1"
SOURCE_MAX_BYTES = 80 * 1024 * 1024


@dataclass(frozen=True)
class F1Project:
    """Explicit binary, CTree and independently pinned sample identity."""
    binary: Path
    binary_id: BinaryId
    ctree: Path
    expected: ExpectedExport
    entry_ea: int
    image_base: int
    allow_partial: bool

    @classmethod
    def from_file(cls, path: Path) -> "F1Project":
        """Resolve Project paths beside its JSON file, never from the export metadata."""
        path = path.resolve(strict=True)
        with path.open("rb") as handle:
            record = read_record(handle.read(65537), max_bytes=65536)
        fields(record, {"project_schema_version", "binary_path", "binary_sha256", "ctree_path",
                        "ctree_sha256", "expected_export_fingerprint", "expected_ida_ea",
                        "expected_image_base", "allow_partial"})
        if record["project_schema_version"] != SCHEMA or type(record["allow_partial"]) is not bool:
            raise ValueError("Unsupported F1 Project schema or partial policy")
        for key in ("binary_path", "ctree_path"):
            if type(record[key]) is not str or not record[key]:
                raise ValueError("Expected explicit F1 input paths")
        return cls(path.parent / record["binary_path"], BinaryId(record["binary_sha256"]),
                   path.parent / record["ctree_path"],
                   ExpectedExport(record["ctree_sha256"], record["expected_export_fingerprint"]),
                   hex_address(record["expected_ida_ea"]), hex_address(record["expected_image_base"]),
                   record["allow_partial"])


def acquire_f1(spec: F1Project, artifact_root: Path) -> F1Reference:
    """Acquire pinned source, lower reloaded HIR, then atomically publish F1 inputs."""
    image = ELFImage.from_path(spec.binary, load_base=spec.image_base)
    project = VerifiedProject.from_elf(image, spec.binary_id, spec.entry_ea, spec.image_base)
    with spec.ctree.open("rb") as handle:
        source_bytes = handle.read(SOURCE_MAX_BYTES + 1)
    source = read_ctree(source_bytes, project, spec.expected)
    hir = decode_hir(encode_hir(build_hir(source)), project.function)
    evidence = capture_evidence(source, image)
    by_hir = {key: evidence["witnesses"][node["source_id"]]
              for key, node in hir.nodes.items() if node["source_id"] in evidence["witnesses"]}
    lowered = lower_hir(hir, by_hir)
    if lowered.cir.completeness != "complete" and not spec.allow_partial:
        raise ValueError("Project forbids semantically partial F1 acquisition")
    return publish_f1(artifact_root, source_bytes, source, hir, lowered, evidence)
