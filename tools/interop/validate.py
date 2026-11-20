"""Read-only validation of the pinned 0x632F8 ELF, IDA, VEX and CTree evidence."""
import argparse
from collections import Counter, defaultdict
from dataclasses import asdict, fields
from hashlib import sha256
import importlib.metadata
from pathlib import Path
import platform
import sys
import tempfile

from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from emtaint.artifacts import AcquisitionRef, load
from emtaint.core.identity import BinaryId, FunctionId
from emtaint.core.contracts import ValueRef
from emtaint.core.wire_json import canonical_json, read_record
from emtaint.f1_artifacts import F1Reference, load_f1
from emtaint.frontends.inputs import ELFImage
from emtaint.ir.canonical.model import operands

ROOT = Path(__file__).resolve().parents[2]
BINARY = "334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787"
VEX_PIN = "c5e46865575c00737c761ae269b2e8e47b5c664e7f936062f9e2bd9359a1e968"
VEX_BODY = "ef7df72a249feb9e75d720b106e61b54ce082017d25a6580d12ae7ddc81a4d10"
F1_PIN = "7a7f459d62053e5c1bcc3be954efaa0e71fb3d1111172ffd83094f719d933b6d"
CTREE_PIN = "209e40012ce07ae79ce95847b5a3792a687536951772877fbd5847ebd06c4c3e"
ENTRY, END, BASE = 0x632F8, 0x6339C, 0x8000
FUNCTION = FunctionId(BinaryId(BINARY), ENTRY - BASE)
VEX_GENERATION = ".f0-runtime/interop-632f8/artifacts/generation-cae3fc8730c44d2ba68ded371c342134"
F1_GENERATION = ".f0-runtime/f1-verification/artifacts/generation-b1a47a88525e47449a2550c939e0e265"
CTREE_PATH = ".f1-input/ctree/ctree_632f8_39ebd8aca9.json"


def check(condition: bool, message: str) -> None:
    """Fail closed on mismatched identities or malformed evidence."""
    if not condition:
        raise ValueError(message)


def file_offset(image: ELFImage, address: int, size: int) -> int:
    """Find the unique executable PT_LOAD mapping for the full instruction."""
    offsets = [offset + address - va for va, offset, filesz, _, flags in image.segments
               if flags & 1 and va <= address and address + size <= va + filesz]
    check(len(offsets) == 1, f"Nonunique executable file mapping: {address:#x}")
    return offsets[0]


def arm_transfer(address: int, data: bytes) -> dict:
    """Decode supported A32 transfer encodings independently of IDA display text."""
    word = int.from_bytes(data, "little")
    if word & 0x0E000000 == 0x0A000000 and word >> 28 != 15:
        signed = (word & 0xFFFFFF) - ((1 << 24) if word & 0x800000 else 0)
        return {"kind": "call" if word & (1 << 24) else "branch",
                "target": address + 8 + 4 * signed, "conditional": word >> 28 != 14}
    if word & 0x0FFF8000 == 0x08BD8000:
        return {"kind": "return", "target": None, "conditional": word >> 28 != 14}
    return {"kind": "other"}


def elf_inventory(image: ELFImage) -> dict[int, dict]:
    """Decode the exact pinned function range through the ELF segment map."""
    check((image.sha256, image.image_base, image.elf_class, image.encoding, image.machine, image.elf_type)
          == (BINARY, BASE, 1, 1, 40, 2), "Unexpected ELF identity")
    decoder = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    rows = {}
    cursor = ENTRY
    for insn in decoder.disasm(image.read(ENTRY, END - ENTRY), ENTRY):
        check(insn.address == cursor and insn.size == 4, "ELF instruction gap or overlap")
        raw = bytes(insn.bytes)
        rows[cursor] = {"ea": cursor, "rva": cursor - BASE, "file_offset": file_offset(image, cursor, 4),
                        "bytes": raw.hex(), "size": 4, "mnemonic": insn.mnemonic,
                        "operands": insn.op_str, "mode": "arm", "transfer": arm_transfer(cursor, raw)}
        cursor += 4
    check(cursor == END, "ELF decoder did not cover the complete function range")
    return rows


def machine_validation(machine: dict, elf: dict[int, dict]) -> dict:
    """Check genuine exported machine data byte-for-byte and validate CFG links."""
    identity = machine["function"]
    check(machine["schema_version"] == "IDA-Machine-Validation-v1", "Invalid IDA evidence version")
    check(identity["binary_sha256"] == BINARY and identity["processor"].upper() == "ARM"
          and identity["ida_version"].split(".")[:2] == ["9", "3"]
          and identity["mode"] == "arm", "IDA binary, processor, version or mode differs")
    for key, value in {"image_base": BASE, "entry_ea": ENTRY, "rva": ENTRY - BASE, "end_ea": END}.items():
        check(int(identity[key], 16) == value, f"IDA {key} differs")
    chunks = [(int(chunk["start_ea"], 16), int(chunk["end_ea"], 16)) for chunk in identity["chunks"]]
    coverage = Counter()
    for start, end in chunks:
        check(ENTRY <= start < end <= END, "IDA chunk outside expected function")
        coverage.update(range(start, end))
    check(set(coverage) == set(range(ENTRY, END)) and set(coverage.values()) == {1}
          and identity["size"] == END - ENTRY, "IDA chunks overlap or do not cover function")
    rows = {}
    mismatches = []
    for record in machine["instructions"]:
        ea = int(record["ea"], 16)
        if ea in rows:
            mismatches.append({"ea": ea, "fields": ["duplicate"]})
        rows[ea] = record
        if ea not in elf:
            mismatches.append({"ea": ea, "fields": ["outside decoded ELF boundary"]})
            continue
        expected = elf[ea]
        actual = {"rva": int(record["rva"], 16), "file_offset": record["file_offset"],
                  "bytes": record["raw_bytes"], "size": record["size"], "mode": record["mode"]}
        discrepancies = [name for name, value in actual.items() if value != expected[name]]
        if record.get("binary_bytes_match") is not True:
            discrepancies.append("IDA binary_bytes_match")
        if discrepancies:
            mismatches.append({"ea": ea, "fields": discrepancies})
    missing = sorted(set(elf) - set(rows))
    blocks = machine["machine_cfg"]["blocks"]
    starts = {int(row["start_ea"], 16): row for row in blocks}
    cfg_issues = []
    assignments = Counter()
    check(len(starts) == len(blocks) and ENTRY in starts, "IDA CFG block list has duplicate or missing entry")
    check([key for key, row in starts.items() if row["entry"]] == [ENTRY], "Invalid IDA entry marker")
    for start, row in starts.items():
        end = int(row["end_ea"], 16)
        instructions = [int(ea, 16) for ea in row["instruction_eas"]]
        assignments.update(instructions)
        if (not ENTRY <= start < end <= END or instructions != list(range(start, end, 4))
                or any(ea not in rows for ea in instructions)):
            cfg_issues.append({"block": start, "reason": "Incomplete or invalid block instruction partition"})
        for direction, reverse in (("successors", "predecessors"), ("predecessors", "successors")):
            for encoded in row[direction]:
                peer = int(encoded, 16)
                if peer not in starts or row["start_ea"] not in starts[peer][reverse]:
                    cfg_issues.append({"block": start, "peer": peer, "reason": f"Invalid {direction} binding"})
        if row["unknown_successor"]:
            cfg_issues.append({"block": start, "reason": "Unknown successor"})
    if set(assignments) != set(rows) or set(assignments.values()) != {1}:
        cfg_issues.append({"reason": "IDA blocks do not partition decoded instructions"})
    if machine["calls"] != [row for row in machine["instructions"] if row["category"] == "call"]:
        cfg_issues.append({"reason": "IDA call inventory disagrees with instruction rows"})
    return {"rows": rows, "blocks": blocks, "mismatches": mismatches, "missing": missing,
            "cfg_issues": cfg_issues, "diagnostics": machine["diagnostics"],
            "matched": len(set(elf) & set(rows) - {item["ea"] for item in mismatches})}


def saved_inputs(vex_path: Path, f1_path: Path, ctree_path: Path, image: ELFImage) -> tuple:
    """Reload both pinned acquisitions and verify their independent source identities."""
    vex = load(AcquisitionRef(vex_path, VEX_PIN), FUNCTION)
    f1 = load_f1(F1Reference(f1_path, F1_PIN))
    ctree_bytes = ctree_path.read_bytes()
    check(vex.artifact_hashes["cir"] == VEX_BODY, "Wrong saved v1 body digest")
    check(sha256(ctree_bytes).hexdigest() == CTREE_PIN == f1.hir.source_sha256, "Wrong CTree source digest")
    tree = read_record(ctree_bytes)
    check(int(tree["function"]["entry_ea"], 16) == ENTRY and int(tree["function"]["end_ea"], 16) == END
          and tree["environment"]["input_file_sha256"] == image.sha256, "Wrong CTree identity or bounds")
    check(vex.cfg.function == f1.hir.function == f1.cir.function == FUNCTION
          and int(f1.manifest["address_mapping"]["image_base"]) == BASE, "Saved function identity mismatch")
    source = vex.report["metadata"]["source_functions"][0]
    check(vex.report["metadata"]["image_base"] == BASE and source["address"] == ENTRY
          and min(row["start"] for row in source["blocks"]) == ENTRY
          and max(row["end"] for row in source["blocks"]) == END
          and all(row["mode"] == "default" and ENTRY <= row["start"] < row["end"] <= END
                  for row in source["blocks"]), "VEX address context, bounds or mode differ")
    return vex, f1, tree


def bind_vex(vex, elf: dict[int, dict], image: ELFImage) -> tuple[dict, list]:
    """Index each statement, source hint and CIR effect without collapsing occurrences."""
    function = vex.module.functions[0]
    origins = {row.id: row for row in vex.module.origin_map}
    hints = {row.origin_id: row for row in vex.provenance.instruction_hints}
    check(origins.keys() == hints.keys(), "VEX Origin and instruction hint inventories differ")
    by_origin = defaultdict(list)
    source_hints = defaultdict(list)
    by_ea = defaultdict(list)
    effects = {}
    values = {value.id: {"type": asdict(value.type), "definitions": [], "uses": []}
              for value in function.values}
    for block in function.blocks:
        for index, effect in enumerate(block.effects):
            identity = f"{block.id.token}:{index}"
            def_ids = []
            uses = []
            for field in fields(effect):
                items = list(operands(getattr(effect, field.name)))
                for ordinal, operand in enumerate(items):
                    reference = isinstance(operand, ValueRef)
                    slot = {"effect": identity, "role": field.name, "ordinal": ordinal}
                    if field.name in {"result", "results"} and reference:
                        def_ids.append(operand.id)
                        values[operand.id]["definitions"].append(slot)
                    else:
                        uses.append({**slot, "operand": asdict(operand), "reference": reference})
                        if reference:
                            values[operand.id]["uses"].append(slot)
            effects[identity] = {"kind": type(effect).__name__, "block_rva": block.id.rva,
                                 "ordinal": index, "payload": asdict(effect),
                                 "definitions": def_ids, "uses": uses}
            by_origin[effect.origin].append(identity)
    for hint in vex.provenance.source_hints:
        source_hints[hint.origin_id].append(asdict(hint))
    statements = {}
    unresolved = []
    for identity, origin in origins.items():
        hint = hints[identity]
        point = origin.point
        check((hint.function_rva, hint.block_rva, hint.statement_index, hint.instruction_rva, hint.source_opcode)
              == (FUNCTION.rva, point.block.rva, point.statement, point.instruction_rva, origin.source_opcode),
              f"Divergent Origin and InstructionHint: {identity}")
        ea = BASE + hint.instruction_rva if hint.instruction_rva is not None else None
        matches = ea in elf and hint.instruction_bytes_hex == elf[ea]["bytes"] and hint.mode == "default"
        if not matches:
            unresolved.append({"origin": identity, "ea": ea, "reason": "Missing or inconsistent machine context"})
        else:
            by_ea[ea].append(identity)
        statements[identity] = {"instruction_hint": asdict(hint), "source_hints": source_hints[identity],
                                "cir_effects": by_origin[identity], "byte_context_verified": matches}
    report = vex.report
    metadata = report["metadata"]
    irsbs = report["block_mappings"]
    for row in irsbs:
        if (row["lift_failure"] or row["function"] != ENTRY or row["mode"] != "default" or
                sha256(image.read(row["irsb_start"], row["irsb_end"] - row["irsb_start"])).hexdigest() != row["byte_sha256"]):
            unresolved.append({"irsb": row["irsb_start"], "reason": "Missing or mismatched IRSB bounds/digest"})
    for row in metadata["native_control_flow"] + report["coverage"]:
        check(row["origin"] in origins and row["function"] == ENTRY, "Invalid VEX report binding")
    return {"origins": statements, "effects": effects, "value_occurrences": values,
            "source_hint_count": len(vex.provenance.source_hints),
            "by_ea": dict(by_ea), "irsbs": irsbs, "native_control_flow": metadata["native_control_flow"],
            "coverage": report["coverage"], "unsupported_ops": report["unsupported_ops"],
            "source_cfg": metadata["source_functions"][0],
            "cir_cfg": {"status": vex.cfg.status.value,
                        "edges": [[e.source.rva, e.target.rva, e.kind.value, e.source.token, e.target.token] for e in
                                  sorted(vex.cfg.edges, key=lambda x: (x.source.rva, x.target.rva, x.kind.value))]},
            "assessment": asdict(vex.module.assessment)}, unresolved


def bind_hir(f1, tree: dict, elf: dict[int, dict]) -> tuple[dict, dict, list]:
    """Preserve CTree location claims and verified witness edges at separate confidence levels."""
    by_ea = defaultdict(list)
    unresolved = []
    for key, row in tree["nodes"].items():
        ea = int(row["ea"], 16) if row["ea"] else None
        if ea in elf:
            by_ea[ea].append(key)
        else:
            unresolved.append({"source": key, "ea": ea, "reason": "No machine instruction anchor"})
    graph = f1.provenance.to_record()
    instructions = f1.evidence["instructions"]
    for key, row in instructions.items():
        ea = row["linked_va"]
        check(ea in elf and row["encoding"] == elf[ea]["bytes"]
              and row["file_offset"] == elf[ea]["file_offset"], f"F1 machine witness disagrees: {key}")
    return {"source_nodes": tree["nodes"], "variables": tree["local_variables"], "types": tree["types"],
            "hir_nodes": f1.hir.nodes, "hir_bindings": graph, "instruction_witnesses": instructions,
            "variables_normalized": f1.hir.variables, "v2_blocks": f1.cir.blocks,
            "v2_effects": {effect["id"]: effect for block in f1.cir.blocks.values() for effect in block["effects"]},
            "structured_cfg": {"status": f1.cfg.status.value,
                               "nodes": [asdict(node) for node in sorted(f1.cfg.nodes, key=lambda node: node.local_id)],
                               "edges": [[e.source.local_id, e.target.local_id, e.kind.value, e.label]
                                         for e in sorted(f1.cfg.edges, key=lambda e: (e.source.local_id,
                                                                                   e.target.local_id, e.kind.value))]}}, dict(by_ea), unresolved


def edge(source: str, target: str, method: str, confidence: str, evidence: str) -> dict:
    """Create an evidence relationship with an explicit non-equivalence interpretation."""
    return {"source": source, "target": target, "method": method, "confidence": confidence,
            "evidence": evidence, "semantic_equivalence": "unverified"}


def coverage_graph(elf: dict[int, dict], machine: dict | None, vex: dict, hir: dict, source_eas: dict) -> dict:
    rows = []
    edges = []
    raw_ida = machine["rows"] if machine else {}
    for ea in elf:
        key = f"elf:{ea:x}"
        origins = vex["by_ea"].get(ea, [])
        nodes = source_eas.get(ea, [])
        witness_ids = [identifier for identifier, row in hir["instruction_witnesses"].items() if row["linked_va"] == ea]
        ida_verified = (machine is not None and ea in raw_ida
                        and ea not in {row["ea"] for row in machine["mismatches"]})
        if ida_verified:
            edges.append(edge(f"ida:{ea:x}", key, "executable-pt-load-and-exact-bytes",
                              "binary-confirmed", "machine-validation.json"))
        for identity in origins:
            edges.append(edge(key, f"vex:{identity}", "pinned-origin-rva-and-instruction-bytes",
                              "byte-context", "vex-origin-mapping.json"))
            for effect_id in vex["origins"][identity]["cir_effects"]:
                edges.append(edge(f"vex:{identity}", f"v1:{effect_id}", "serialized-effect-origin",
                                  "producer-reported", "vex-origin-mapping.json"))
        for identity in nodes:
            edges.append(edge(key, f"ctree:{identity}", "same-address-anchor-only",
                              "location-only", "ctree-hir-mapping.json"))
        for identity in witness_ids:
            edges.append(edge(key, f"f1-insn:{identity}", "stored-machine-witness-exact-bytes",
                              "binary-confirmed", "ctree-hir-mapping.json"))
        effects = [effect_id for identity in origins for effect_id in vex["origins"][identity]["cir_effects"]]
        status = ["LIFTED"] if origins else []
        if effects:
            status.append("REPRESENTED_BY_EFFECTS")
        if nodes:
            status.append("STRUCTURED_SOURCE")
        if not effects and origins and elf[ea]["transfer"]["kind"] in {"branch", "call", "return"}:
            status.append("CONTROL_ONLY")
        if not status:
            status = ["UNMAPPED"]
        rows.append({"ea": ea, "ida": "BYTE_VERIFIED" if ida_verified else
                     ("UNAVAILABLE" if machine is None else "UNVERIFIED"),
                     "vex_origins": origins, "v1_effects": effects, "ctree_nodes": nodes,
                     "f1_machine_witnesses": witness_ids, "coverage": status})
    for relationship in hir["hir_bindings"]["edges"]:
        names = {"source": "ctree", "hir": "hir", "instruction": "f1-insn",
                 "effect": "v2", "block": "f1-block", "definition": "v2-definition", "use": "v2-use"}
        left, right = relationship["source"], relationship["target"]
        edges.append({**edge(f"{names[left[0]]}:{left[1]}", f"{names[right[0]]}:{right[1]}",
                             relationship["method"], relationship["confidence"], "ctree-hir-mapping.json"),
                      "relation": relationship["relation"], "status": relationship["status"],
                      "reason": relationship["reason"]})
    return {"instruction_coverage": rows, "edges": edges, "conflicts": hir["hir_bindings"]["conflicts"]}


def control_evidence(machine: dict | None, vex: dict, hir: dict, elf: dict[int, dict]) -> dict:
    """Keep machine, VEX and synthetic control boundaries separately attributable."""
    source = vex["source_cfg"]
    ida_blocks = machine["blocks"] if machine else []
    starts = {int(block["start_ea"], 16): block for block in ida_blocks}
    comparison = []
    edge_comparison = []
    angr_edges = {tuple(row) for row in source["edges"]}
    ida_rows = machine["rows"] if machine else {}
    native_by_ea = defaultdict(list)
    for transfer in vex["native_control_flow"]:
        hint = vex["origins"][transfer["origin"]]["instruction_hint"]
        if hint["instruction_rva"] is not None:
            native_by_ea[BASE + hint["instruction_rva"]].append(transfer)
    v1_by_id = vex["effects"]
    v1_at = {ea: [v1_by_id[key] for identity in origins for key in vex["origins"][identity]["cir_effects"]]
             for ea, origins in vex["by_ea"].items()}
    f1_at = defaultdict(list)
    for identity, effect in hir["v2_effects"].items():
        witness = hir["instruction_witnesses"].get(effect["instruction_origin"])
        if witness:
            f1_at[witness["linked_va"]].append(identity)
    for start, block in starts.items():
        end = int(block["end_ea"], 16)
        pieces = [row for row in source["blocks"] if start <= row["start"] < end]
        covered = {address for piece in pieces for address in range(piece["start"], piece["end"], 4)}
        joined = all((left["start"], right["start"]) in angr_edges for left, right in zip(pieces, pieces[1:]))
        if block["unknown_successor"] or not joined:
            status = "PARTIAL"
        elif covered != set(range(start, end, 4)):
            status = "PARTIAL" if covered else "UNAVAILABLE"
        else:
            status = "EXACT" if len(pieces) == 1 else "NORMALIZED"
        comparison.append({"ida_block": start, "end": end, "angr_pieces": pieces, "boundary_status": status})
        if not block["instruction_eas"]:
            continue
        tail = int(block["instruction_eas"][-1], 16)
        model = elf[tail]["transfer"]
        targets = {int(target, 16) for target in block["successors"]}
        if model["kind"] == "branch":
            elf_targets = {model["target"]} | ({tail + 4} if model["conditional"] else set())
        elif model["kind"] == "return":
            elf_targets = {tail + 4} if model["conditional"] else set()
        else:
            elf_targets = {tail + 4} if tail + 4 in starts else None
        for target in sorted(targets | (elf_targets or set())):
            if elf_targets is not None and (target in targets) != (target in elf_targets):
                edge_status = "CONFLICT"
            elif not pieces or elf_targets is None:
                edge_status = "UNAVAILABLE"
            elif (pieces[-1]["start"], target) not in angr_edges:
                edge_status = "PARTIAL"
            else:
                edge_status = "EXACT" if len(pieces) == 1 else "NORMALIZED"
            edge_comparison.append({"ida_source": start, "terminator_ea": tail,
                                    "target": target, "in_ida": target in targets,
                                    "in_elf": target in elf_targets if elf_targets is not None else None,
                                    "status": edge_status})
    probes = []
    for ea in (0x63320, 0x63340, 0x63354, 0x6335C, 0x63364, 0x63370, 0x6337C, 0x63388, 0x6338C, 0x63394, 0x63398):
        probes.append({"ea": ea, "elf": elf[ea]["transfer"], "ida": ida_rows.get(ea),
                       "vex_native": native_by_ea[ea], "v1_effect_kinds": [row["kind"] for row in v1_at.get(ea, ())],
                       "f1_witness_effects": f1_at[ea]})
    machine_successors = {(int(block["start_ea"], 16), int(target, 16))
                          for block in ida_blocks for target in block["successors"]}
    v1_edges = []
    for source_rva, target_rva, kind, source_id, target_id in vex["cir_cfg"]["edges"]:
        start, target = BASE + source_rva, BASE + target_rva
        owner = next((begin for begin, block in starts.items() if begin <= start < int(block["end_ea"], 16)), None)
        status = "UNAVAILABLE" if owner is None else "PARTIAL"
        if kind != "unknown" and (owner, target) in machine_successors:
            status = "NORMALIZED"
        v1_edges.append({"source": source_id, "target": target_id, "kind": kind,
                         "ida_block_candidate": owner, "target_ea": target, "status": status,
                         "method": "source address containment and declared target; guard equivalence unverified"})
    structured_edges = []
    for source_id, target_id, kind, guard in hir["structured_cfg"]["edges"]:
        terminal = hir["v2_blocks"][source_id]["effects"][-1]
        witness = hir["instruction_witnesses"].get(terminal["instruction_origin"])
        structured_edges.append({"source": source_id, "target": target_id, "kind": kind, "guard": guard,
                                 "machine_terminator_ea": witness["linked_va"] if witness else None,
                                 "status": "PARTIAL" if witness else "UNAVAILABLE"})
    return {"ida_blocks": ida_blocks, "boundary_comparison": comparison,
            "edge_comparison": edge_comparison, "probes": probes,
            "v1_edge_comparison": v1_edges, "structured_edge_comparison": structured_edges,
            "angr_cfg": source, "vex_exits": vex["native_control_flow"], "v1_cfg": vex["cir_cfg"],
            "structured_cfg": hir["structured_cfg"],
            "machine_transfers": {str(ea): row["transfer"] for ea, row in elf.items()
                                  if row["transfer"]["kind"] != "other"}}


def effect_evidence(vex: dict, hir: dict, elf: dict[int, dict], graph: dict, machine: dict | None) -> dict:
    """Summarize observable effects and preserve full effect records for manual validation."""
    rows = []
    calls = []
    machine_rows = machine["rows"] if machine else {}
    for record in graph["instruction_coverage"]:
        ea = record["ea"]
        effects = [vex["effects"][key] for key in record["v1_effects"]]
        rows.append({"ea": ea, "machine": elf[ea], "counts": dict(Counter(row["kind"] for row in effects)),
                     "ordered_effect_records": effects, "ctree_nodes": record["ctree_nodes"],
                     "witness_status": "candidate-effects-through-provenance",
                     "unverified": ["reaching register/memory state", "source-level ABI and clobber",
                                    "cross-representation guard and operand equivalence"]})
        if elf[ea]["transfer"]["kind"] != "call":
            continue
        ida = machine_rows.get(ea)
        v1_calls = [row["payload"] for row in effects if row["kind"] == "CallEffect"]
        targets = [BASE + call["target"]["function"]["rva"] for call in v1_calls
                   if call["target"].get("function", {}).get("binary", {}).get("sha256") == BINARY]
        f1_sites = [effect for effect in hir["v2_effects"].values()
                    if effect["op"] == "call" and effect["instruction_origin"] in record["f1_machine_witnesses"]]
        machine_target = elf[ea]["transfer"]["target"]
        ida_target = int(ida["direct_target_ea"], 16) if ida and ida["direct_target_ea"] else None
        calls.append({"site_ea": ea, "elf_target": machine_target, "ida_target": ida_target,
                      "ida_thunk": ida["target_is_ida_thunk"] if ida else None, "v1_calls": v1_calls,
                      "v1_direct_targets": targets, "f1_calls": f1_sites,
                      "physical_target_status": "UNAVAILABLE" if ida is None else
                      ("EXACT" if ida_target == machine_target and targets == [machine_target] else "CONFLICT"),
                      "source_arguments_and_side_effects": "PARTIAL"})
    by_ea = {row["ea"]: row for row in rows}
    byte_read = [row["payload"] for row in by_ea[0x63368]["ordered_effect_records"] if row["kind"] == "LoadEffect"]
    byte_witnesses = {key for key, witness in hir["instruction_witnesses"].items()
                      if witness["linked_va"] == 0x63368}
    source_reads = [effect for effect in hir["v2_effects"].values()
                    if effect["op"] == "read_memory" and effect["instruction_origin"] in byte_witnesses]
    v1_widths = [effect["width_bits"] for effect in byte_read]
    v2_widths = [effect["data"]["width_bytes"] for effect in source_reads]
    ret = [effect for effect in hir["v2_effects"].values() if effect["op"] == "return"]
    return {"rows": rows, "calls": calls, "conflicts": graph["conflicts"], "vex_unsupported": vex["unsupported_ops"],
            "local_checks": {
                "byte_load": {"ea": 0x63368, "elf_mnemonic": elf[0x63368]["mnemonic"],
                              "v1_widths_bits": v1_widths, "v2_widths_bytes": v2_widths,
                              "status": "WIDTH_ALIGNED_ONLY" if v1_widths == [8] and v2_widths == [1]
                              else "PARTIAL", "memory_object_and_guard": "unverified"},
                "return_candidate": {"elf_assignment": elf[0x63380], "machine_return": elf[0x63388],
                                     "v1_returns": [row["payload"] for row in by_ea[0x63388]["ordered_effect_records"]
                                                    if row["kind"] == "ReturnEffect"],
                                     "v2_returns": ret, "observable_state_equivalence": "unverified"},
                "loop_candidate": {"elf_back_edge": elf[0x6337C]["transfer"],
                                   "hir_variable_merges": {key: block["parameters"]
                                                          for key, block in hir["v2_blocks"].items()
                                                          if block["parameters"]},
                                   "state_correspondence": "blocked pending shared register and guard semantics"},
            },
            "v2_effect_count": len(hir["v2_effects"]),
            "v1_effect_counts": dict(Counter(row["kind"] for row in vex["effects"].values()))}


def write_bundle(output_root: Path, payloads: dict[str, dict | list | bytes], inputs: dict) -> Path:
    """Publish a fresh local evidence directory with a manifest written last."""
    output_root.mkdir(parents=True, exist_ok=True)
    run = Path(tempfile.mkdtemp(prefix="validation-", dir=output_root))
    files = {}
    for name, record in payloads.items():
        data = record if isinstance(record, bytes) else canonical_json(record)
        with (run / name).open("xb") as handle:
            handle.write(data)
        files[name] = {"sha256": sha256(data).hexdigest(), "size": len(data)}
    manifest = canonical_json({"schema": "BinaryAnalysis-Local-Translation-Validation-v1",
                               "inputs": inputs, "files": files})
    with (run / "sha256-manifest.json").open("xb") as handle:
        handle.write(manifest)
    print(f"bundle={run}")
    print(f"manifest_sha256={sha256(manifest).hexdigest()}")
    return run


def verify_bundle(run: Path, pin: str) -> int:
    """Recheck the evidence bundle without loading IDA or the original databases."""
    data = (run / "sha256-manifest.json").read_bytes()
    check(sha256(data).hexdigest() == pin, "Wrong evidence manifest digest")
    manifest = read_record(data)
    check(manifest["schema"] == "BinaryAnalysis-Local-Translation-Validation-v1", "Unknown evidence format")
    for name, desc in manifest["files"].items():
        check(Path(name).name == name and name.endswith(".json") and ":" not in name, "Invalid evidence path")
        path = run / name
        check(not path.is_symlink() and path.resolve().parent == run.resolve(), "Evidence path leaves bundle")
        size = desc["size"]
        check(type(size) is int and 0 <= size <= 80 * 1024 * 1024, "Invalid evidence byte budget")
        with path.open("rb") as handle:
            raw = handle.read(size + 1)
        check(len(raw) == size and sha256(raw).hexdigest() == desc["sha256"], f"Evidence hash mismatch: {name}")
        read_record(b'{"payload":' + raw + b"}", max_bytes=size + 12)
    machine_pin = manifest["inputs"]["machine_sha256"]
    if machine_pin is not None:
        check(manifest["files"]["machine-validation.json"]["sha256"] == machine_pin,
              "Archived machine digest disagrees with original input pin")
    print(f"verified_files={len(manifest['files'])}")
    return 0


def main() -> int:
    """Validate evidence or verify an existing digest-pinned bundle."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--vex", type=Path, default=ROOT / VEX_GENERATION)
    parser.add_argument("--f1", type=Path, default=ROOT / F1_GENERATION)
    parser.add_argument("--ctree", type=Path, default=ROOT / CTREE_PATH)
    parser.add_argument("--machine", type=Path)
    parser.add_argument("--machine-pin")
    parser.add_argument("--environment", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--verify", type=Path)
    parser.add_argument("--pin")
    args = parser.parse_args()
    try:
        if args.verify:
            return verify_bundle(args.verify, args.pin)
        check(args.binary is not None and args.output is not None, "--binary and --output are required")
        check((args.machine is None) == (args.machine_pin is None), "Machine file requires an external SHA-256 pin")
        image = ELFImage.from_path(args.binary)
        elf = elf_inventory(image)
        vex, f1, tree = saved_inputs(args.vex, args.f1, args.ctree, image)
        vex_map, vex_gaps = bind_vex(vex, elf, image)
        hir, source_eas, hir_gaps = bind_hir(f1, tree, elf)
        machine_record = None
        machine = None
        if args.machine:
            raw = args.machine.read_bytes()
            check(sha256(raw).hexdigest() == args.machine_pin, "Wrong external machine digest")
            machine_record = read_record(raw)
            machine = machine_validation(machine_record, elf)
        relationships = coverage_graph(elf, machine, vex_map, hir, source_eas)
        control = control_evidence(machine, vex_map, hir, elf)
        effects = effect_evidence(vex_map, hir, elf, relationships, machine)
        machine_ready = machine is not None and not machine["mismatches"] and not machine["missing"]
        report = {
            "levels": {"0_input_identity": "PASS" if machine else "PARTIAL",
                       "1_instruction_coverage": "BLOCKED" if machine is None else
                       ("PASS" if machine_ready and not vex_gaps else "FAIL"),
                       "2_control_flow": "PARTIAL" if machine_ready else "BLOCKED",
                       "3_effect_mapping": "PARTIAL" if machine_ready else "BLOCKED",
                       "4_semantic_translation": "BLOCKED"},
            "blockers": (["Authentic IDA machine evidence unavailable"] if machine is None else [])
                        + ["Shared semantics and v1-to-v2 adapter await ACR approval"],
            "counts": {"elf_instructions": len(elf), "ida_instructions": len(machine["rows"]) if machine else None,
                       "ida_byte_matches": machine["matched"] if machine else None,
                       "ida_blocks": len(machine["blocks"]) if machine else None,
                       "ida_edges": sum(len(b["successors"]) for b in machine["blocks"]) if machine else None,
                       "vex_origins": len(vex_map["origins"]), "vex_instruction_anchors": len(vex_map["by_ea"]),
                       "vex_source_hints": vex_map["source_hint_count"], "v1_effects": len(vex_map["effects"]),
                       "ctree_nodes": len(tree["nodes"]), "ctree_instruction_anchors": len(source_eas),
                       "ctree_hir_unmapped_nodes": len(hir_gaps), "evidence_edges": len(relationships["edges"])},
            "machine_validation": {key: value for key, value in machine.items() if key != "rows"} if machine else None,
            "vex_unresolved": vex_gaps, "ctree_without_machine_anchor": hir_gaps,
            "conflicts": relationships["conflicts"],
            "comparison_scope": "read-only evidence validation with explicit sources and uncertainty",
        }
        inputs = {"binary_sha256": BINARY, "function": asdict(FUNCTION), "image_base": BASE, "end": END,
                  "vex_manifest_sha256": VEX_PIN, "vex_body_sha256": VEX_BODY, "f1_manifest_sha256": F1_PIN,
                  "ctree_sha256": CTREE_PIN, "machine_sha256": args.machine_pin}
        environment = read_record(args.environment.read_bytes()) if args.environment else {}
        environment.update({"python": platform.python_version(), "capstone": importlib.metadata.version("capstone"),
                            "validator_sha256": sha256(Path(__file__).read_bytes()).hexdigest(),
                            "validation_strategy": "PT_LOAD, typed saved identities and explicit provenance"})
        payloads = {"environment.json": environment, "elf-instructions.json": list(elf.values()),
                    "machine-cfg.json": control, "vex-origin-mapping.json": vex_map, "ctree-hir-mapping.json": hir,
                    "evidence-graph.json": relationships, "effect-mapping.json": effects, "validation-report.json": report}
        if machine_record is not None:
            payloads["machine-validation.json"] = raw
        write_bundle(args.output, payloads, inputs)
        print(canonical_json({"levels": report["levels"], "counts": report["counts"]}).decode())
        return 0 if machine_ready and not vex_gaps else 2
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(f"Validation failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
