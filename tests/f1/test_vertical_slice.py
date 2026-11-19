"""Real pinned F1 acceptance through the public CLI and detached artifact reader."""
from collections import Counter
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from emtaint.artifacts import ArtifactError, IntegrityStatus
from emtaint.core.identity import BinaryId, ProgramBlockId
from emtaint.core.wire_json import canonical_json
from emtaint.f1_acquisition import F1Project, acquire_f1
from emtaint.f1_artifacts import F1Reference, load_f1
from emtaint.frontends.ctree_source import ExpectedExport, VerifiedProject, build_hir, export_fingerprint, read_ctree
from emtaint.frontends.inputs import ELFImage
from emtaint.ir.canonical.wire_v2 import CIRFunctionV2, decode_cir, encode_cir
from emtaint.ir.hir.model import decode_hir, encode_hir

ROOT = Path(__file__).resolve().parents[2]
CTREE = ROOT / ".f1-input/ctree/ctree_632f8_39ebd8aca9.json"
BINARY = Path(os.environ.get("F1_BINARY", r"D:\Codes\firmware-binaries\rv130_v44\httpd"))
BINARY_ID = BinaryId("334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787")
PIN = ExpectedExport(
    "209e40012ce07ae79ce95847b5a3792a687536951772877fbd5847ebd06c4c3e",
    "86b88fbfda634919dab74241ce008ba00a424cf3d67c096e5cb5cf3ea015a0c8",
)
ENTRY = 0x632F8
BASE = 0x8000


def repin(document: dict) -> tuple[bytes, ExpectedExport]:
    document["export_fingerprint"] = export_fingerprint(document)
    data = canonical_json(document)
    return data, ExpectedExport(hashlib.sha256(data).hexdigest(), document["export_fingerprint"])


class F1Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.directory = tempfile.TemporaryDirectory(prefix="f1-verification-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.root = Path(cls.directory.name)
        cls.spec = F1Project(BINARY, BINARY_ID, CTREE, PIN, ENTRY, BASE, True)
        cls.reference = acquire_f1(cls.spec, cls.root / "generations")
        cls.inputs = load_f1(cls.reference)
        cls.project = VerifiedProject.from_elf(ELFImage.from_path(BINARY), BINARY_ID, ENTRY, BASE)

    def test_ctree_identity_structure_and_hir_round_trip(self) -> None:
        source = read_ctree(CTREE.read_bytes(), self.project, PIN)
        self.assertEqual(Counter(row["category"] for row in source.document["nodes"].values()),
                         {"statement": 13, "expression": 40})
        hir = self.inputs.hir
        self.assertEqual((len(hir.nodes), sum(len(row["children"]) for row in hir.nodes.values()),
                          len(hir.variables), len(hir.types)), (53, 52, 6, 23))
        self.assertEqual(hir.export_fingerprint, PIN.fingerprint)
        self.assertEqual(len({row["opcode"] for row in source.document["nodes"].values()}), 19)
        self.assertNotIn("Opaque", {node["kind"] for node in hir.nodes.values()})
        self.assertEqual(encode_hir(decode_hir(encode_hir(hir), hir.function)), encode_hir(hir))
        variables = {row["index"]: (key, row) for key, row in hir.variables.items()}
        self.assertNotEqual(variables[0][0], variables[3][0])
        self.assertEqual(variables[0][1]["storage"], variables[3][1]["storage"])
        self.assertTrue(variables[5][1]["user_name"])
        self.assertFalse(variables[5][1]["user_type"])
        self.assertTrue(any(row["evidence"]["raw_source"] == "hexrays_inferred_or_user"
                            and row["evidence"]["source"] == "HEX_RAYS_REPORTED"
                            for row in hir.types.values()))

    def test_pin_and_structural_rejections(self) -> None:
        data = CTREE.read_bytes()
        document = json.loads(data)
        with self.assertRaisesRegex(ValueError, "CTree SHA-256"):
            read_ctree(data + b" ", self.project, PIN)
        with self.assertRaisesRegex(ValueError, "fingerprint"):
            read_ctree(data, self.project, replace(PIN, fingerprint="0" * 64))
        with self.assertRaisesRegex(ValueError, "binary SHA-256"):
            read_ctree(data, replace(self.project, function=replace(self.project.function,
                                                                    binary=BinaryId("0" * 64))), PIN)
        with self.assertRaisesRegex(ValueError, "image base"):
            read_ctree(data, replace(self.project, image_base=BASE + 4), PIN)
        with self.assertRaisesRegex(ValueError, "Duplicate JSON key"):
            read_ctree(b'{"x":1,"x":2}', self.project, PIN)
        dereference = next(key for key, row in document["nodes"].items() if row["opcode"] == "cot_ptr")
        variable = next(key for key, row in document["nodes"].items() if row["opcode"] == "cot_var")
        for edit, message in (
            (lambda row: row["environment"].update(source_address_domain="RVA"), "address domain"),
            (lambda row: row["function"].update(entry_ea="0x632fc"), "function address"),
            (lambda row: row["nodes"]["node:root"]["children"].reverse(), "role or ordinal"),
            (lambda row: row["nodes"]["node:root"]["children"][0].update(id="absent"), "tree reference"),
            (lambda row: row["nodes"][dereference].update(type_id="absent"), "type"),
            (lambda row: row["nodes"][variable]["attributes"].update(lvar_index=99), "variable"),
            (lambda row: row.update(schema_version="other"), "source version"),
        ):
            changed = deepcopy(document)
            edit(changed)
            modified, pin = repin(changed)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                read_ctree(modified, self.project, pin)
        with patch("emtaint.frontends.ctree_source.MAX_NODES", 52):
            with self.assertRaisesRegex(ValueError, "budget"):
                read_ctree(data, self.project, PIN)
        with patch("emtaint.ir.hir.model.MAX_DEPTH", 8):
            with self.assertRaisesRegex(ValueError, "over-depth"):
                read_ctree(data, self.project, PIN)

    def test_opaque_preserves_known_children_and_flags_truncation(self) -> None:
        for status, missing in (("represented", "KNOWN_CHILDREN"), ("partial-structure", "UNKNOWN_CHILDREN"),
                                ("truncated", "TRUNCATED")):
            with self.subTest(status=status):
                document = json.loads(CTREE.read_bytes())
                original = next(node for node in document["nodes"].values() if node["opcode"] == "cot_ptr")
                original.update(opcode="cot_future", opcode_value=999, status=status)
                document["op_histogram"]["cot_future"] = document["op_histogram"].pop("cot_ptr")
                data, pin = repin(document)
                hir = decode_hir(encode_hir(build_hir(read_ctree(data, self.project, pin))))
                node = next(row for row in hir.nodes.values() if row["source_id"] == original["id"])
                self.assertEqual((hir.assessment, node["kind"], node["payload"]["subtree"]),
                                 ("partial", "Opaque", missing))
                self.assertEqual(node["payload"]["raw"], original)
                self.assertEqual(len(node["children"]), 1)
                self.assertTrue(node["payload"]["footprint"]["control"])

    def test_cir_loop_guards_calls_and_memory(self) -> None:
        loaded = self.inputs
        cir = loaded.cir
        self.assertEqual(loaded.semantic_completeness.value, "partial")
        effects = [effect for block in cir.blocks.values() for effect in block["effects"]]
        calls = sorted((effect for effect in effects if effect["op"] == "call"),
                       key=lambda effect: effect["instruction_origin"])
        self.assertEqual([call["data"]["argument_count"] for call in calls], [2, 5, 1, 2])
        self.assertEqual([call["data"]["result_used"] for call in calls], [False, False, True, False])
        for call in calls:
            self.assertTrue(call["data"]["footprint"]["unknown"])
            self.assertEqual(call["data"]["target"]["kind"], "direct_address")
            self.assertIsNone(call["data"]["abi"])
        self.assertEqual(calls[0]["data"]["target"]["address"], 0xFFF4)
        conditions = [effect for effect in effects if effect["op"] == "branch"]
        self.assertEqual(len(conditions), 3)
        loop = next(row for row in loaded.hir.nodes.values() if row["kind"] == "For")
        self.assertEqual([c["role"] for c in loop["children"]], ["init", "condition", "step", "body"])
        self.assertEqual(loop["evaluation"]["roles"], ["init", "condition", "body", "step", "condition"])
        header = next(key for key in cir.blocks if key.startswith("header:"))
        variable = next(key for key, row in loaded.hir.variables.items() if row["name"] == "i")
        phi = next(row for row in cir.blocks[header]["parameters"]
                   if cir.definitions[row["definition"]]["variable"] == variable)
        self.assertEqual({key.split(":", 1)[0] for key in phi["incoming"]}, {"init", "latch"})
        for role, operation in (("init", "copy"), ("latch", "add")):
            block = next(key for key in phi["incoming"] if key.startswith(role + ":"))
            self.assertEqual(next(effect["op"] for effect in cir.blocks[block]["effects"]
                                  if phi["incoming"][block] in effect["outputs"]), operation)
        header_effects = cir.blocks[header]["effects"]
        self.assertTrue(any(use["definition"] == phi["definition"]
                            for effect in header_effects for use in effect["uses"]))
        memory = [effect for effect in effects if effect["op"] == "read_memory"]
        self.assertEqual(len(memory), 1)
        self.assertEqual(memory[0]["data"]["width_bytes"], 1)
        self.assertIsNone(memory[0]["data"]["object"])
        access = next(effect for effect in effects if effect["data"].get("index_unit") == "element")
        self.assertEqual(access["op"], "symbolic_address")
        self.assertIsNone(access["data"]["byte_offset"])
        self.assertEqual(len(loaded.cfg.exits), 1)
        self.assertEqual(loaded.cfg.status.value, "incomplete")
        returned = next(effect for effect in effects if effect["op"] == "return")
        return_def = returned["uses"][0]["definition"]
        self.assertEqual(next(effect["data"]["value"] for effect in effects if return_def in effect["outputs"]), 0)
        self.assertTrue(all(isinstance(node, ProgramBlockId) for node in loaded.cfg.nodes))
        node = next(node for node in loaded.cfg.nodes if node.local_id == header)
        self.assertTrue(node.synthetic)
        self.assertEqual(node.anchor_domain, "IDA_EA")
        self.assertEqual(
            {target.local_id.split(":", 1)[0] for target in loaded.cfg.successors(node)}, {"body", "exit"},
        )
        self.assertEqual(decode_cir(encode_cir(cir)).body_digest, cir.body_digest)
        invalid = json.loads(encode_cir(cir))
        del invalid["blocks"][header]["parameters"][0]["incoming"][next(iter(phi["incoming"]))]
        with self.assertRaisesRegex(ValueError, "exactly the predecessors"):
            decode_cir(canonical_json(invalid))

    def test_provenance_and_no_ea(self) -> None:
        provenance = self.inputs.provenance
        self.assertEqual(provenance.conflicts[0]["id"], "helper-machine-call")
        self.assertTrue(any(row["lowering"] == "no_effect" for row in provenance.coverage.values()))
        no_ea = next(key for key, row in self.inputs.hir.nodes.items() if row["address"] is None)
        self.assertTrue(provenance.related("hir", no_ea))
        machine = provenance.related("instruction", "arm:63368")
        self.assertGreaterEqual(len(machine), 2)
        branch = next(edge["source"][1] for edge in machine
                      if edge["source"][0] == "effect" and edge["source"][1] != machine[0]["source"][1])
        self.assertTrue(any(edge["target"] == ["instruction", "arm:63370"]
                            for edge in provenance.related("effect", branch)))
        self.assertTrue(any(edge["target"][0] == "use" for edge in provenance.edges))

    def test_cli_and_independent_process_inspection(self) -> None:
        spec_path = self.root / "project.json"
        spec_path.write_bytes(canonical_json({
            "project_schema_version": "ProjectSpec-F1-v1", "binary_path": str(BINARY),
            "binary_sha256": BINARY_ID.sha256, "ctree_path": str(CTREE), "ctree_sha256": PIN.sha256,
            "expected_export_fingerprint": PIN.fingerprint, "expected_ida_ea": hex(ENTRY),
            "expected_image_base": hex(BASE), "allow_partial": True,
        }))
        base = [sys.executable, "-B", "-m", "emtaint", "f1"]
        run = subprocess.run(base + ["acquire", "--project", str(spec_path), "--artifact-root",
                                     str(self.root / "cli")], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(run.returncode, 0, run.stderr)
        receipt = json.loads(run.stdout)
        run = subprocess.run(base + ["inspect", "--generation", receipt["generation"],
                                     "--manifest-sha256", receipt["manifest_sha256"], "--related",
                                     "instruction", "arm:63368"], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertGreaterEqual(len(json.loads(run.stdout)["related"]), 2)
        guard = """
import os,sys
from pathlib import Path
from emtaint.f1_artifacts import F1Reference, load_f1
blocked = {os.path.normcase(os.path.abspath(path)) for path in sys.argv[3:]}
def reject_originals(event, args):
    if event == 'open' and isinstance(args[0], (str, bytes)):
        assert os.path.normcase(os.path.abspath(os.fsdecode(args[0]))) not in blocked
sys.addaudithook(reject_originals)
loaded = load_f1(F1Reference(Path(sys.argv[1]), sys.argv[2]))
assert len(loaded.hir.nodes) == 53
assert not {'idaapi', 'ida_hexrays', 'angr', 'cle', 'pyvex', 'archinfo'} & sys.modules.keys()
"""
        run = subprocess.run([sys.executable, "-B", "-c", guard, receipt["generation"],
                              receipt["manifest_sha256"], str(BINARY), str(CTREE)],
                             capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(run.returncode, 0, run.stderr)
        regenerated = load_f1(F1Reference(Path(receipt["generation"]), receipt["manifest_sha256"]))
        self.assertEqual(regenerated.manifest["artifacts"], self.inputs.manifest["artifacts"])

    def _copy(self, label: str) -> F1Reference:
        path = self.root / label / self.reference.generation.name
        shutil.copytree(self.reference.generation, path)
        return replace(self.reference, generation=path)

    def test_detached_tamper_path_stale_version_and_partial_policy(self) -> None:
        for kind, descriptor in self.inputs.manifest["artifacts"].items():
            with self.subTest(kind=kind):
                ref = self._copy(f"tamper-{kind}")
                output = ref.generation / descriptor["path"]
                output.write_bytes(output.read_bytes() + b"x")
                with self.assertRaises(ArtifactError) as error:
                    load_f1(ref)
                self.assertEqual(error.exception.status, IntegrityStatus.CORRUPT)
        for kind, expected in (("path", IntegrityStatus.CORRUPT),
                               ("version", IntegrityStatus.INCOMPATIBLE)):
            ref = self._copy(kind)
            manifest = deepcopy(self.inputs.manifest)
            if kind == "path":
                manifest["artifacts"]["hir"]["path"] = "../escape.json"
            else:
                manifest["schema_version"] = "AcquisitionManifest-F1-v99"
            data = canonical_json(manifest)
            (ref.generation / "manifest.json").write_bytes(data)
            with self.assertRaises(ArtifactError) as error:
                load_f1(replace(ref, manifest_sha256=hashlib.sha256(data).hexdigest()))
            self.assertEqual(error.exception.status, expected)
        with self.assertRaises(ArtifactError) as error:
            load_f1(self.reference, current_export=replace(PIN, sha256="0" * 64))
        self.assertEqual(error.exception.status, IntegrityStatus.STALE)
        output = self.root / "forbidden"
        with self.assertRaisesRegex(ValueError, "semantically partial"):
            acquire_f1(replace(self.spec, allow_partial=False), output)
        self.assertFalse(output.exists())

    def test_publication_failure_leaves_no_generation(self) -> None:
        root = self.root / "injected-failure"
        with patch("emtaint.f1_artifacts._load", side_effect=ValueError("injected staging failure")):
            with self.assertRaisesRegex(ValueError, "injected staging failure"):
                acquire_f1(self.spec, root)
        self.assertEqual(list(root.iterdir()), [])

    def test_common_cir_memory_write_width(self) -> None:
        def effect(index: int, op: str, *, data: dict | None = None,
                   output: str | None = None, operands: tuple = ()) -> dict:
            effect_id = f"entry/effect/{index}"
            return {"id": effect_id, "op": op, "outputs": [output] if output else [],
                    "uses": [{"id": f"{effect_id}/use/{role}/0", "definition": value,
                              "role": role, "ordinal": 0} for role, value in operands],
                    "data": data or {}, "instruction_origin": None, "provenance": []}

        pointer, value = "entry/input/0", "entry/input/1"
        block = {"origin_kind": "synthetic", "anchor_domain": None, "anchor_address": None,
                 "inputs": [pointer, value], "parameters": [], "effects": [
                     effect(0, "write_memory", data={"width_bytes": 1},
                            operands=(("address", pointer), ("value", value))),
                     effect(1, "return"),
                 ]}
        cir = CIRFunctionV2(self.project.function, "test-common-producer", "entry", {"entry": block}, {
            pointer: {"kind": "input", "type": {"kind": "pointer", "bits": 32}, "variable": None},
            value: {"kind": "input", "type": {"kind": "integer", "bits": 8}, "variable": None},
        }, "complete", [])
        self.assertEqual(decode_cir(encode_cir(cir)), cir)
        block["effects"][0]["data"]["width_bytes"] = 2
        with self.assertRaisesRegex(ValueError, "Memory write operand"):
            encode_cir(cir)
