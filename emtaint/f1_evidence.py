"""Source-qualified machine evidence and many-to-many F1 provenance."""
import hashlib
import struct

from emtaint.analysis_debugging.representation_provenance import ProvenanceGraph
from emtaint.core.wire_json import fields
from emtaint.frontends.ctree_source import ValidatedCTree, VerifiedProject
from emtaint.frontends.inputs import ELFImage
from emtaint.ir.canonical.hir_lowering import Lowering
from emtaint.ir.canonical.wire_v2 import CIRFunctionV2, phi_use_id
from emtaint.ir.hir.model import HIRFunction

SCHEMA = "F1-ARM-InstructionEvidence-v1"
PINNED_SOURCE = "209e40012ce07ae79ce95847b5a3792a687536951772877fbd5847ebd06c4c3e"
ARM_BODY = "node:root/statement[1]/body[0]"
CALL_WITNESSES = (
    ("node:root/statement[0]/expression[0]", 0x63320, 0xFFF4, "strcpy"),
    (f"{ARM_BODY}/statement[0]/expression[0]", 0x63354, 0x10390, None),
    (f"{ARM_BODY}/statement[1]/expression[0]/y[0]/x[0]", 0x6335C, 0x1D170, None),
    (f"{ARM_BODY}/statement[3]/then[0]/statement[0]/expression[0]", 0x63394, 0x62B30, None),
)
BYTE_CONDITION = f"{ARM_BODY}/statement[3]/condition[0]"


def _arm_bl(address: int, word: int) -> int:
    if word >> 24 != 0xEB:
        raise ValueError("Expected an unconditional ARM BL")
    displacement = word & 0xFFFFFF
    if displacement & 0x800000:
        displacement -= 1 << 24
    return address + 8 + 4 * displacement


def capture_evidence(source: ValidatedCTree, image: ELFImage) -> dict:
    """Record explicitly audited correspondences for the owner's pinned sample."""
    evidence: dict = {"schema_version": SCHEMA, "instructions": {}, "witnesses": {}}
    if source.expected.sha256 != PINNED_SOURCE:
        return evidence
    nodes = source.document["nodes"]

    def capture(address: int, operation: str, expected: int, *, branch: bool = False) -> str:
        data = image.read(address, 4)
        word, = struct.unpack("<I", data)
        if (_arm_bl(address, word) if branch else word) != expected:
            raise ValueError("ELF no longer agrees with the audited instruction witness")
        key = f"arm:{address:x}"
        evidence["instructions"][key] = {
            "linked_va": address, "rva": address - source.project.image_base,
            "file_offset": source.project.file_offset(address, 4, executable=True),
            "encoding": data.hex(), "operation": operation,
        }
        return key

    for source_id, address, target, helper in CALL_WITNESSES:
        node = nodes[source_id]
        callee = nodes[node["children"][0]["id"]]["attributes"]
        if (node["opcode"], node["ea"]) != ("cot_call", hex(address)) or (
                callee.get("helper_name") != helper if helper else callee.get("object_ea") != hex(target)):
            raise ValueError("Source call does not match the audited witness")
        instruction = capture(address, "bl", target, branch=True)
        evidence["witnesses"][source_id] = {"instructions": [instruction], "branch_target": target,
                                            "helper": helper}
    node = nodes[BYTE_CONDITION]
    if node["opcode"] != "cot_ptr" or node["attributes"].get("pointer_access_size_bytes") != 1:
        raise ValueError("Source dereference does not match the audited witness")
    ids = [capture(address, op, word) for address, op, word in (
        (0x63368, "ldrb", 0xE5D03000), (0x6336C, "cmp_zero", 0xE3530000),
        (0x63370, "branch_nonzero", 0x1A000005),
    )]
    evidence["witnesses"][BYTE_CONDITION] = {"instructions": ids, "branch_instruction": ids[-1]}
    return evidence


def validate_evidence(evidence: dict, source: ValidatedCTree) -> None:
    """Validate saved instruction references and segment conversions during reload."""
    fields(evidence, {"schema_version", "instructions", "witnesses"})
    if evidence["schema_version"] != SCHEMA:
        raise ValueError("Unsupported machine evidence")
    instructions = evidence["instructions"]
    witnesses = evidence["witnesses"]
    if type(instructions) is not dict or type(witnesses) is not dict:
        raise ValueError("Invalid evidence tables")
    expected_sources = {row[0] for row in CALL_WITNESSES} | {BYTE_CONDITION}
    if source.expected.sha256 == PINNED_SOURCE and set(witnesses) != expected_sources:
        raise ValueError("Pinned sample machine witnesses are incomplete")
    if source.expected.sha256 != PINNED_SOURCE and (instructions or witnesses):
        raise ValueError("Machine witness is outside the audited source revision")
    seen = set()
    for source_id, witness in witnesses.items():
        if source_id not in source.document["nodes"] or type(witness.get("instructions")) is not list:
            raise ValueError("Invalid machine evidence source")
        for key in witness["instructions"]:
            seen.add(key)
            row = instructions[key]
            fields(row, {"linked_va", "rva", "file_offset", "encoding", "operation"})
            address = row["linked_va"]
            data = bytes.fromhex(row["encoding"])
            if (type(address) is not int or address % 4 or len(data) != 4 or key != f"arm:{address:x}"
                    or row["rva"] != address - source.project.image_base
                    or row["file_offset"] != source.project.file_offset(address, 4, executable=True)):
                raise ValueError("Invalid instruction identity or address conversion")
            if "branch_target" in witness and _arm_bl(address, int.from_bytes(data, "little")) != witness["branch_target"]:
                raise ValueError("Machine branch target mismatch")
    if seen != set(instructions):
        raise ValueError("Unreferenced instruction evidence")
    if witnesses:
        for source_id, address, target, helper in CALL_WITNESSES:
            if witnesses[source_id] != {"instructions": [f"arm:{address:x}"],
                                        "branch_target": target, "helper": helper}:
                raise ValueError("Pinned call witness changed")
        if witnesses[BYTE_CONDITION] != {"instructions": ["arm:63368", "arm:6336c", "arm:63370"],
                                         "branch_instruction": "arm:63370"}:
            raise ValueError("Pinned byte-condition witness changed")
        for key, operation, encoding in (
            ("arm:63368", "ldrb", "0030d0e5"), ("arm:6336c", "cmp_zero", "000053e3"),
            ("arm:63370", "branch_nonzero", "0500001a"),
        ):
            if (instructions[key]["operation"], instructions[key]["encoding"]) != (operation, encoding):
                raise ValueError("Pinned instruction encoding changed")


def inventories(hir: HIRFunction, cir: CIRFunctionV2, evidence: dict) -> dict[str, set[str]]:
    """Enumerate valid local endpoint IDs without lowering or native tools."""
    effects = [effect for block in cir.blocks.values() for effect in block["effects"]]
    phi_uses = {phi_use_id(parameter["definition"], predecessor)
                for block in cir.blocks.values() for parameter in block["parameters"]
                for predecessor in parameter["incoming"]}
    return {"source": {node["source_id"] for node in hir.nodes.values()}, "hir": set(hir.nodes),
            "block": set(cir.blocks), "effect": {effect["id"] for effect in effects},
            "definition": set(cir.definitions), "instruction": set(evidence["instructions"]),
            "use": {use["id"] for effect in effects for use in effect["uses"]} | phi_uses}


def build_provenance(hir: HIRFunction, lowered: Lowering, evidence: dict,
                     namespaces: dict[str, str]) -> ProvenanceGraph:
    """Join structured lowering records with explicit ARM machine witnesses."""
    cir = lowered.cir
    edges = []
    conflicts = []
    coverage = {}
    for key, node in sorted(hir.nodes.items()):
        coverage[key] = {"lowering": "no_effect", "instruction_mapping": "unavailable",
                         "reason": "No direct CIR effect emitted for this structured node"}
        if node["coverage"] == "unsupported":
            coverage[key].update(lowering="unsupported", reason=node["payload"]["reason"])

    def edge(left: list[str], right: list[str], relation: str, reason: str, *,
             status: str = "mapped", confidence: str = "ANALYSIS_DERIVED",
             method: str = "structured-lowering-v1") -> None:
        edges.append({"source": left, "target": right, "relation": relation, "status": status,
                      "confidence": confidence, "method": method, "reason": reason})

    for key, node in sorted(hir.nodes.items()):
        edge(["source", node["source_id"]], ["hir", key], "normalizes_to", "Validated source node",
             status="mapped" if node["coverage"] == "represented" else "partial",
             confidence="DECOMPILER_RECOVERED", method=hir.normalizer)
    for block_id, block in sorted(cir.blocks.items()):
        block_source = lowered.block_sources[block_id]
        edge(["hir", block_source], ["block", block_id], "derives",
             "Structured control lowering; no machine block entry inferred")
        for definition_id in block["inputs"]:
            edge(["hir", block_source], ["definition", definition_id], "derives", "Function parameter input")
        for parameter in block["parameters"]:
            definition_id = parameter["definition"]
            edge(["hir", block_source], ["definition", definition_id], "derives", "Predecessor-indexed merge")
            for predecessor in sorted(parameter["incoming"]):
                edge(["hir", block_source], ["use", phi_use_id(definition_id, predecessor)], "derives",
                     "Incoming definition on predecessor edge")
        for effect in block["effects"]:
            effect_id = effect["id"]
            endpoints = [["effect", effect_id]]
            endpoints.extend(["definition", value] for value in effect["outputs"])
            endpoints.extend(["use", use["id"]] for use in effect["uses"])
            for key in effect["provenance"]:
                partial = (effect["op"] in {"unknown", "symbolic_address", "call", "unknown_exit"}
                           or effect["data"].get("partial", False))
                status = "partial" if partial else "mapped"
                row = coverage[key]
                if row["lowering"] != "unsupported" and (partial or row["lowering"] == "no_effect"):
                    row.update(lowering="partial" if partial else "lowered", reason="Structured lowering effect")
                for endpoint in endpoints:
                    edge(["hir", key], endpoint, "lowers_to", "Ordered CIR lowering", status=status)
                source_id = hir.nodes[key]["source_id"]
                witness = evidence["witnesses"].get(source_id, {})
                if effect["instruction_origin"] not in witness.get("instructions", ()):
                    continue
                machine_ids = (witness["instructions"] if effect["op"] == "branch"
                               else [effect["instruction_origin"]])
                if witness.get("helper"):
                    row["instruction_mapping"] = "ambiguous"
                    conflicts.append({
                        "id": "helper-machine-call", "property": "call representation",
                        "facts": [["source", source_id], ["effect", effect_id], ["instruction", machine_ids[0]]],
                        "status": "unresolved",
                        "reason": "Hex-Rays strcpy helper versus binary BL target and audited memcpy presentation",
                    })
                else:
                    row["instruction_mapping"] = "partial"
                for machine_id in machine_ids:
                    edge(["effect", effect_id], ["instruction", machine_id], "corresponds_to",
                         "Explicit source-shape and ARM opcode/operand witness",
                         status="ambiguous" if witness.get("helper") else "partial",
                         confidence="BINARY_CONFIRMED", method="pinned-arm-witness-v1")
    record = ProvenanceGraph(cir.function.token, namespaces, tuple(edges), coverage, tuple(conflicts))
    return ProvenanceGraph.from_record(record.to_record(), cir.function.token, namespaces,
                                       inventories(hir, cir, evidence))
