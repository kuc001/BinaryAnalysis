"""Pure contract checks independent of IDA, ELF and local generations."""
from copy import deepcopy
from dataclasses import replace
import json
import unittest

from emtaint.core.identity import BinaryId, FunctionId
from emtaint.core.wire_json import canonical_json
from emtaint.ir.canonical.hir_lowering import lower_hir
from emtaint.ir.canonical.wire_v2 import CIRFunctionV2, decode_cir, encode_cir, graph, validate_cfg_record, cfg_record
from emtaint.ir.hir.model import HIRFunction, decode_hir, encode_hir

FUNCTION = FunctionId(BinaryId("0" * 64), 0)


def make_cir(effects: list[dict], *, inputs: tuple = (), definitions: dict | None = None) -> CIRFunctionV2:
    """Build an isolated one-block wire specimen."""
    return CIRFunctionV2(FUNCTION, "contract-test", "entry", {
        "entry": {"origin_kind": "synthetic", "anchor_domain": None, "anchor_address": None,
                  "inputs": list(inputs), "parameters": [], "effects": effects},
    }, definitions or {}, "partial", [])


def effect(ordinal: int, op: str, data: dict | None = None, operands: tuple = (), outputs: tuple = ()) -> dict:
    key = f"entry/effect/{ordinal}"
    return {"id": key, "op": op, "data": data or {}, "outputs": list(outputs),
            "uses": [{"id": f"{key}/use/{role}/{index}", "role": role, "ordinal": index, "definition": definition}
                     for role, index, definition in operands],
            "provenance": [], "instruction_origin": None}


def make_hir() -> HIRFunction:
    """Build a standalone HIR tree with a mandatory role and two statements."""
    hir = HIRFunction(FUNCTION, "1" * 64, "2" * 64, "contract-test", "", {}, {}, {}, "complete")

    def add(kind, category, source, children=(), **overrides):
        key = hir.identity("node:" + category, source)
        hir.nodes[key] = {
            "kind": kind, "category": category, "source_id": source, "children": list(children),
            "address": None, "type_id": None, "payload": {}, "evaluation": {},
            "coverage": "represented", "value_role": "statement" if category == "statement" else "value",
            **overrides,
        }
        return key

    literal = add("Constant", "expression", "literal", payload={"numeric_value_hex": "0x1"})
    ret = add("Return", "statement", "return", ({"id": literal, "role": "value", "index": 0},))
    root = add("Block", "statement", "root", ({"id": ret, "role": "statement", "index": 0},))
    return replace(hir, entry=root)


class PureContracts(unittest.TestCase):
    def test_partial_semantics_with_complete_structured_cfg(self):
        addr = "entry/input/0"
        target_type = {"kind": "input", "type": {"kind": "pointer", "bits": 32}, "variable": None}
        call = effect(0, "call", {"argument_count": 0, "target": {"kind": "unknown", "reason": "test"},
                                 "footprint": {"unknown": True, "read": ["*"], "write": ["*"], "clobber": ["*"]},
                                 "evaluation_order": "unknown", "result_used": False,
                                 "guard": {"kind": "block_reachability", "block": "entry"}},
                      (("callee", 0, addr),))
        body = decode_cir(encode_cir(make_cir([call, effect(1, "return")], inputs=(addr,),
                                               definitions={addr: target_type})))
        self.assertEqual(body.completeness, "partial")
        self.assertEqual(graph(body).status.value, "complete")
        invalid = json.loads(encode_cir(body))
        invalid["blocks"]["entry"]["effects"][0]["data"]["target"] = {
            "kind": "direct_address", "domain": "RVA", "address": "bad"}
        with self.assertRaises(ValueError):
            decode_cir(canonical_json(invalid))

    def test_unknown_exit_and_opaque_control_are_incomplete(self):
        cir = make_cir([effect(0, "unknown_exit", {"reason": "unknown successor"})])
        self.assertEqual(graph(decode_cir(encode_cir(cir))).status.value, "incomplete")
        forged = cfg_record(cir)
        forged["status"] = "complete"
        with self.assertRaisesRegex(ValueError, "CFG disagrees"):
            validate_cfg_record(forged, cir)
        hir = make_hir()
        hir.nodes[hir.entry].update(kind="Opaque", coverage="unsupported", payload={
            "raw": {"children": [{"id": "return", "role": "statement", "index": 0}]},
            "opcode": "unknown_control", "opcode_value": 999, "reason": "unknown",
            "subtree": "KNOWN_CHILDREN", "footprint": {"read": True, "write": True, "control": True},
        })
        hir = decode_hir(encode_hir(replace(hir, assessment="partial")))
        lowered = lower_hir(hir, {}).cir
        self.assertEqual(graph(decode_cir(encode_cir(lowered))).status.value, "incomplete")
        unknown = effect(0, "unknown", {
            "reason": "Opaque control inside a structured block", "may_change_control": True,
            "footprint": {"unknown": True, "read": ["*"], "write": ["*"], "clobber": ["*"]},
        })
        cir = make_cir([unknown, effect(1, "return")])
        self.assertEqual(graph(decode_cir(encode_cir(cir))).status.value, "incomplete")

    def test_malformed_hir_independent_of_source_reader(self):
        original = json.loads(encode_hir(make_hir()))
        ret = next(key for key, node in original["nodes"].items() if node["kind"] == "Return")
        for edit, message in (
            (lambda row: row["nodes"][row["entry"]]["children"][0].update(role="expression"), "child roles"),
            (lambda row: row["nodes"][ret]["children"][0].update(role="value extra"), "role token"),
            (lambda row: row["nodes"][ret].update(kind="HelperRef"), "node kind"),
            (lambda row: row["nodes"][ret].update(type_id="missing"), "Dangling HIR type"),
            (lambda row: row["nodes"][ret]["children"][0].update(id="missing"), "tree reference"),
        ):
            record = deepcopy(original)
            edit(record)
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                decode_hir(canonical_json(record))

    def test_malformed_cir_independent_of_lowerer(self):
        original = json.loads(encode_cir(make_cir([effect(0, "return")])))
        invalid_effects = (
            (effect(0, "jump"), "record fields"),
            (effect(0, "jump", {"target": "missing"}), "Dangling CIR control"),
            (effect(0, "unknown_exit", {"reason": 1}), "Unknown exit"),
            (effect(0, "return", operands=(("return", 0, "missing"),)), "Dangling CIR use"),
        )
        for invalid, message in invalid_effects:
            record = deepcopy(original)
            record["blocks"]["entry"]["effects"] = [invalid]
            with self.subTest(message=message), self.assertRaisesRegex(ValueError, message):
                decode_cir(canonical_json(record))
        record = deepcopy(original)
        fake = effect(0, "unknown", {"reason": "unknown", "may_change_control": True, "footprint": None})
        record["blocks"]["entry"]["effects"] = [fake, effect(1, "return")]
        with self.assertRaisesRegex(ValueError, "explicit result or footprint"):
            decode_cir(canonical_json(record))
