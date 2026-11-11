"""F0 contract and real firmware acquisition/reload verification."""

from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from emtaint.acquisition import FrontendSelection, acquire
from emtaint.artifacts import (
    AcquisitionRef, ArtifactError, ArtifactRoot, IntegrityStatus,
    SemanticCompleteness, load,
)
from emtaint.core import BinaryId, FunctionId
from emtaint.frontends.inputs import InputError
from emtaint.frontends.saved_cir import load_saved_cir
from emtaint.project import ProjectSpec, ResolvedInputs, resolve


BINARY_SHA256 = "334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787"
DEFAULT_BINARY = (
    Path(__file__).resolve().parents[3] / "firmware-binaries" / "rv130_v44" / "httpd"
)


def _binary() -> Path:
    return Path(os.environ.get("F0_BINARY", str(DEFAULT_BINARY)))


def _spec(path: Path, *, sha256: str = BINARY_SHA256,
          va: int = 0x10E58, base: int = 0x8000,
          allow_partial: bool = True) -> ProjectSpec:
    return ProjectSpec(path, sha256, "angr-vex", (va,), base, allow_partial)


def _json_bytes(record: object) -> bytes:
    return json.dumps(record, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False, allow_nan=False).encode("utf-8")


class ProjectInputTests(unittest.TestCase):
    """Gate F0-1, using the approved ELF and explicit failure variants."""

    @classmethod
    def setUpClass(cls) -> None:
        if not _binary().is_file():
            raise unittest.SkipTest("Approved rv130_v44/httpd binary is unavailable")

    def test_valid_binary_address_and_thumb_mapping(self) -> None:
        inputs = resolve(_spec(_binary()))
        self.assertIsInstance(inputs, ResolvedInputs)
        self.assertEqual(inputs.binary_id.sha256, BINARY_SHA256)
        self.assertEqual((inputs.elf_class, inputs.encoding, inputs.elf_type, inputs.machine),
                         (1, 1, 2, 40))
        self.assertEqual((inputs.image_base, inputs.selected_va, inputs.function_rva),
                         (0x8000, 0x10E58, 0x8E58))
        self.assertEqual(inputs.instruction_mode, "default")
        thumb = resolve(_spec(_binary(), va=0x10E59))
        self.assertEqual((thumb.selected_va, thumb.physical_va, thumb.function_rva,
                          thumb.instruction_mode), (0x10E59, 0x10E58, 0x8E58, "thumb"))

    def test_invalid_binary_hash_base_and_address(self) -> None:
        with self.assertRaisesRegex(InputError, "SHA-256 mismatch"):
            resolve(_spec(_binary(), sha256="0" * 64))
        with self.assertRaisesRegex(InputError, "base"):
            resolve(_spec(_binary(), base=0x9000))
        with self.assertRaisesRegex(InputError, "executable"):
            resolve(_spec(_binary(), va=0x7000))
        with self.assertRaisesRegex(InputError, "word-aligned"):
            resolve(_spec(_binary(), va=0x10E5A))
        with self.assertRaises(FileNotFoundError):
            resolve(_spec(_binary().with_name("missing-httpd")))

    def test_unsupported_architecture(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "unsupported.elf"
            data = bytearray(_binary().read_bytes())
            struct.pack_into("<H", data, 18, 0xFFFF)
            path.write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            with self.assertRaisesRegex(InputError, "frontend mapping"):
                resolve(_spec(path, sha256=digest))

    def test_project_file_rejects_extra_fields_and_duplicate_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "project.json"
            record = {
                "project_schema_version": "ProjectSpec-F0-v1",
                "binary_path": str(_binary()),
                "binary_sha256": BINARY_SHA256,
                "frontend": "angr-vex",
                "function_vas": ["0x10e58"],
                "expected_image_base": "0x8000",
                "allow_partial": True,
            }
            path.write_bytes(_json_bytes(record))
            self.assertEqual(resolve(ProjectSpec.from_file(path)).function_rva, 0x8E58)
            record["extra"] = True
            path.write_bytes(_json_bytes(record))
            with self.assertRaisesRegex(InputError, "exactly"):
                ProjectSpec.from_file(path)
            path.write_text('{"frontend":"angr-vex","frontend":"angr-vex"}', encoding="utf-8")
            with self.assertRaisesRegex(InputError, "Duplicate"):
                ProjectSpec.from_file(path)


class RealAcquisitionTests(unittest.TestCase):
    """Gates F0-2/3 with one actual CFGFast/VEX acquisition."""

    @classmethod
    def setUpClass(cls) -> None:
        if not _binary().is_file():
            raise unittest.SkipTest("Approved rv130_v44/httpd binary is unavailable")
        # angr keeps an LMDB handle for its native recovery database on
        # Windows. Keep this ignored verification directory until process exit.
        cls.directory = Path(tempfile.mkdtemp(prefix="f0-verify-"))
        cls.spec = _spec(_binary())
        cls.inputs = resolve(cls.spec)
        cls.outcome = acquire(cls.inputs, FrontendSelection(),
                              ArtifactRoot(cls.directory / "artifacts"))
        cls.reference = cls.outcome.reference
        cls.function = cls.outcome.function

    def _copy_generation(self, label: str) -> tuple[AcquisitionRef, dict[str, object]]:
        directory = self.directory / label / self.reference.generation.name
        shutil.copytree(self.reference.generation, directory)
        manifest = json.loads((directory / "manifest.json").read_text(encoding="utf-8"))
        return AcquisitionRef(directory, self.reference.manifest_sha256), manifest

    @staticmethod
    def _pin_manifest(reference: AcquisitionRef, manifest: dict[str, object]) -> AcquisitionRef:
        data = _json_bytes(manifest)
        (reference.generation / "manifest.json").write_bytes(data)
        return AcquisitionRef(reference.generation, hashlib.sha256(data).hexdigest())

    def test_real_frontend_and_saved_records(self) -> None:
        loaded = load(self.reference, self.function, project=self.spec)
        self.assertEqual(self.function, FunctionId(BinaryId(BINARY_SHA256), 0x8E58))
        self.assertEqual(loaded.integrity, IntegrityStatus.VALID)
        self.assertEqual(loaded.semantic_completeness, SemanticCompleteness.PARTIAL)
        self.assertEqual(len(loaded.module.functions[0].blocks), 1)
        self.assertEqual(sum(len(block.effects) for block in loaded.module.functions[0].blocks), 95)
        self.assertEqual(len(loaded.module.origin_map), 74)
        self.assertEqual(len(loaded.provenance.source_hints), 119)
        self.assertEqual(len(loaded.provenance.instruction_hints), 74)
        self.assertEqual((len(loaded.cfg.nodes), len(loaded.cfg.edges)), (1, 0))
        self.assertEqual(loaded.report["statement_status_counts"]["lowered"], 62)
        self.assertEqual(loaded.report["statement_status_counts"]["metadata"], 11)
        saved_module, saved_report, saved_hashes = load_saved_cir(self.reference.generation)
        self.assertEqual(saved_module.functions[0].function_id, self.function)
        self.assertEqual(saved_report, loaded.report)
        self.assertEqual(saved_hashes[self.function], loaded.artifact_hashes["cir"])

    def test_independent_process_reload_without_native_modules(self) -> None:
        code = (
            "import json,sys; from pathlib import Path; "
            "from emtaint.artifacts import AcquisitionRef,load; "
            "from emtaint.core import BinaryId,FunctionId; "
            "ref=AcquisitionRef(Path(sys.argv[1]),sys.argv[2]); "
            "f=load(ref,FunctionId(BinaryId(sys.argv[3]),int(sys.argv[4],16))); "
            "print(json.dumps({'integrity':f.integrity.value,"
            "'semantic':f.semantic_completeness.value,"
            "'cir_sha256':f.artifact_hashes['cir'],'origins':len(f.module.origin_map),"
            "'cfg_nodes':len(f.cfg.nodes),"
            "'native_imports':[x for x in ('angr','pyvex','cle','archinfo') "
            "if x in sys.modules]}))"
        )
        run = subprocess.run(
            [sys.executable, "-c", code, str(self.reference.generation),
             self.reference.manifest_sha256, BINARY_SHA256, "8e58"],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(run.returncode, 0, run.stderr)
        record = json.loads(run.stdout)
        self.assertEqual(record["native_imports"], [])
        self.assertEqual((record["integrity"], record["semantic"], record["origins"]),
                         ("valid", "partial", 74))
        self.assertEqual(
            record["cir_sha256"], load(self.reference, self.function).artifact_hashes["cir"],
        )

    def test_each_artifact_and_manifest_tamper(self) -> None:
        _, manifest = self._copy_generation("tamper-template")
        for kind in ("source", "cir", "cfg", "origins", "source_hints", "instruction_hints"):
            with self.subTest(kind=kind):
                reference, _ = self._copy_generation("tamper-" + kind)
                path = reference.generation / manifest["artifacts"][kind]["path"]
                path.write_bytes(path.read_bytes() + b"X")
                with self.assertRaises(ArtifactError) as raised:
                    load(reference, self.function)
                self.assertEqual(raised.exception.status, IntegrityStatus.CORRUPT)
        reference, _ = self._copy_generation("tamper-manifest")
        path = reference.generation / "manifest.json"
        path.write_bytes(path.read_bytes() + b"X")
        with self.assertRaises(ArtifactError) as raised:
            load(reference, self.function)
        self.assertEqual(raised.exception.status, IntegrityStatus.CORRUPT)

    def test_missing_schema_and_function_identity(self) -> None:
        reference, manifest = self._copy_generation("missing-file")
        (reference.generation / manifest["artifacts"]["cfg"]["path"]).unlink()
        with self.assertRaises(ArtifactError) as raised:
            load(reference, self.function)
        self.assertEqual(raised.exception.status, IntegrityStatus.MISSING)
        reference, manifest = self._copy_generation("bad-schema")
        manifest["schema_version"] = "AcquisitionManifest-F0-v9"
        reference = self._pin_manifest(reference, manifest)
        with self.assertRaises(ArtifactError) as raised:
            load(reference, self.function)
        self.assertEqual(raised.exception.status, IntegrityStatus.INCOMPATIBLE)
        reference, manifest = self._copy_generation("bad-cir-schema")
        manifest["artifacts"]["cir"]["schema_version"] = "CIR-Wire-v9"
        reference = self._pin_manifest(reference, manifest)
        with self.assertRaises(ArtifactError) as raised:
            load(reference, self.function)
        self.assertEqual(raised.exception.status, IntegrityStatus.INCOMPATIBLE)
        with self.assertRaises(ArtifactError) as raised:
            load(self.reference, FunctionId(BinaryId(BINARY_SHA256), 0x8E59))
        self.assertEqual(raised.exception.status, IntegrityStatus.STALE)
        with self.assertRaises(ArtifactError) as raised:
            load(
                self.reference, self.function,
                project=replace(self.spec, expected_image_base=0x9000),
            )
        self.assertEqual(raised.exception.status, IntegrityStatus.STALE)

    def test_dangling_cfg_and_provenance_references(self) -> None:
        for label, kind, change in (
            ("dangling-cfg", "cfg", lambda row: row["edges"].append({
                "source": row["nodes"][0], "target": "0" * 64,
                "kind": "jump", "label": "invalid"})),
            ("dangling-origin", "origins", lambda row: row[next(iter(row))].update({
                "block": "0" * 64})),
            ("dangling-hint-origin", "source_hints", lambda row: row["hints"][0].update({
                "origin_id": "missing"})),
            ("dangling-hint-value", "source_hints", lambda row: row["hints"][0].update({
                "value_id": "missing"})),
        ):
            with self.subTest(label=label):
                reference, manifest = self._copy_generation(label)
                path = reference.generation / manifest["artifacts"][kind]["path"]
                record = json.loads(path.read_text(encoding="utf-8"))
                change(record)
                data = _json_bytes(record)
                path.write_bytes(data)
                manifest["artifacts"][kind]["size"] = len(data)
                manifest["artifacts"][kind]["sha256"] = hashlib.sha256(data).hexdigest()
                reference = self._pin_manifest(reference, manifest)
                with self.assertRaises(ArtifactError) as raised:
                    load(reference, self.function)
                self.assertEqual(raised.exception.status, IntegrityStatus.CORRUPT)

    def test_paths_and_unpublished_staging(self) -> None:
        for label, path in (("traversal", "../escape.json"),
                            ("absolute", "C:/escape.json")):
            with self.subTest(label=label):
                reference, manifest = self._copy_generation(label)
                manifest["artifacts"]["cfg"]["path"] = path
                reference = self._pin_manifest(reference, manifest)
                with self.assertRaises(ArtifactError) as raised:
                    load(reference, self.function)
                self.assertEqual(raised.exception.status, IntegrityStatus.CORRUPT)
        with self.assertRaises(ValueError):
            AcquisitionRef(
                self.directory / ".staging-f0-incomplete", self.reference.manifest_sha256,
            )

    def test_link_escape_is_rejected(self) -> None:
        reference, manifest = self._copy_generation("linked-cfg")
        path = reference.generation / manifest["artifacts"]["cfg"]["path"]
        path.unlink()
        try:
            os.symlink(self.reference.generation / manifest["artifacts"]["cfg"]["path"], path)
        except OSError as error:
            # Windows may deny symbolic links but permit directory junctions.
            # A junction is also a link escape and must be rejected.
            if os.name != "nt":
                self.skipTest("Symlink creation unavailable: " + str(error))
            outside = self.directory / "outside-cfg"
            outside.mkdir()
            shutil.copyfile(self.reference.generation / manifest["artifacts"]["cfg"]["path"],
                            outside / path.name)
            path.parent.rmdir()
            creation = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(path.parent), str(outside)],
                capture_output=True, text=True, check=False,
            )
            if creation.returncode != 0:
                self.skipTest("Windows link creation unavailable: " + creation.stderr)
        with self.assertRaises(ArtifactError) as raised:
            load(reference, self.function)
        self.assertEqual(raised.exception.status, IntegrityStatus.CORRUPT)

    def test_link_guard_when_windows_denies_link_creation(self) -> None:
        import emtaint.artifacts as artifact_module

        reference, manifest = self._copy_generation("link-guard")
        link_directory = reference.generation / manifest["artifacts"]["cfg"]["path"]
        link_directory = link_directory.parent
        real_is_link = artifact_module._is_link
        with patch.object(
            artifact_module, "_is_link",
            side_effect=lambda path: path == link_directory or real_is_link(path),
        ):
            with self.assertRaises(ArtifactError) as raised:
                load(reference, self.function)
        self.assertEqual(raised.exception.status, IntegrityStatus.CORRUPT)

    def test_partial_forbidden_and_detached_binary(self) -> None:
        forbidden = replace(self.spec, allow_partial=False)
        output = self.directory / "forbidden"
        with self.assertRaisesRegex(InputError, "partial"):
            acquire(resolve(forbidden), FrontendSelection(), ArtifactRoot(output))
        self.assertFalse(output.exists())

        copied_binary = self.directory / "source-httpd"
        shutil.copyfile(_binary(), copied_binary)
        copied_spec = _spec(copied_binary)
        outcome = acquire(resolve(copied_spec), FrontendSelection(),
                          ArtifactRoot(self.directory / "detached"))
        copied_binary.unlink()
        self.assertFalse(copied_binary.exists())
        self.assertEqual(load(outcome.reference, outcome.function).integrity, IntegrityStatus.VALID)
        with self.assertRaises(ArtifactError) as raised:
            load(outcome.reference, outcome.function, project=copied_spec)
        self.assertEqual(raised.exception.status, IntegrityStatus.STALE)


if __name__ == "__main__":
    unittest.main()
