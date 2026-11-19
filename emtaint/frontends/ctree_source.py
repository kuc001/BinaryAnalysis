"""Strict serialized CTree adapter and normalization into common HIR."""
from collections import Counter
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from hashlib import sha256
from typing import Any

from emtaint.core.identity import BinaryId, FunctionId
from emtaint.core.wire_json import canonical_json, digest_text, fields, hex_address, read_record, table
from emtaint.frontends.inputs import ELFImage
from emtaint.ir.hir.model import HIRFunction, MAX_NODES, MAX_TYPES, validate_tree

SCHEMA = "IDA-CTree-Source-F1-draft-v2"
CAPABILITY = "CTree-F1-Capability-v1"
NORMALIZER = "CTree-HIR-v1"
ENVIRONMENT = {"ida_version": "9.3", "hexrays_version": "9.3.0.251224",
               "python_version": "3.15.2", "processor": "ARM", "source_address_domain": "IDA_EA",
               "no_ea_marker": "null", "type_encoding": "bounded_structural_hints_not_lossless"}
STATEMENTS = {
    "cit_block": ("Block", ("statement*",)), "cit_expr": ("ExpressionStatement", ("expression",)),
    "cit_for": ("For", ("init", "condition", "step", "body")),
    "cit_if": ("If", ("condition", "then", "else?")), "cit_return": ("Return", ("value?",)),
}
EXPRESSIONS = {
    "cot_asg": ("Assign", ("x", "y")), "cot_call": ("Call", ("callee", "argument*")),
    "cot_cast": ("Cast", ("x",)), "cot_helper": ("HelperRef", ()),
    "cot_idx": ("ArrayAccess", ("x", "y")), "cot_lnot": ("Unary", ("x",)),
    "cot_ne": ("Binary", ("x", "y")), "cot_num": ("Constant", ()),
    "cot_obj": ("AddressedObjectRef", ()), "cot_preinc": ("Unary", ("x",)),
    "cot_ptr": ("Dereference", ("x",)), "cot_ref": ("AddressOf", ("x",)),
    "cot_str": ("Constant", ()), "cot_var": ("VariableRef", ()),
}


@dataclass(frozen=True)
class VerifiedProject:
    """Identity and file-backed ranges established from ELF or a pinned manifest."""

    function: FunctionId
    image_base: int
    segments: tuple[tuple[int, int, int, int, int], ...]

    @classmethod
    def from_elf(cls, image: ELFImage, binary: BinaryId, entry_ea: int, image_base: int) -> "VerifiedProject":
        if image.sha256 != binary.sha256 or image.image_base != image_base:
            raise ValueError("Project binary SHA-256 or image base mismatch")
        if (image.elf_class, image.encoding, image.elf_type, image.machine) != (1, 1, 2, 40):
            raise ValueError("F1 expects ARM little-endian ELF32 ET_EXEC")
        image.read(entry_ea, 4)
        if entry_ea % 4:
            raise ValueError("Expected word-aligned ARM entry")
        return cls(FunctionId(binary, entry_ea - image_base), image_base, tuple(image.segments))

    def file_offset(self, linked_va: int, size: int, *, executable: bool = False) -> int:
        """Convert through the declared file-backed PT_LOAD map."""
        offsets = [offset + linked_va - va for va, offset, filesz, _, flags in self.segments
                   if va <= linked_va < linked_va + size <= va + filesz and (not executable or flags & 1)]
        if len(offsets) != 1:
            raise ValueError("Address has no unique file-backed mapping")
        return offsets[0]


@dataclass(frozen=True)
class ExpectedExport:
    """External pin and exporter semantic fingerprint."""
    sha256: str
    fingerprint: str


@dataclass(frozen=True)
class ValidatedCTree:
    """Validated source record with its binary and source identity."""
    project: VerifiedProject
    expected: ExpectedExport
    document: dict[str, Any]


def export_fingerprint(document: dict) -> str:
    """Reproduce the v2 exporter fingerprint, excluding time and local path."""
    identity = {key: value for key, value in document.items()
                if key not in {"exported_at_utc", "export_fingerprint", "environment"}}
    identity["environment"] = {key: value for key, value in document["environment"].items()
                               if key != "input_file_path"}
    return sha256(canonical_json(identity)).hexdigest()


def _role_sequence(expected: tuple[str, ...], children: list[dict]) -> None:
    remaining = [child["role"] for child in children]
    index = 0
    for token in expected:
        role = token.rstrip("*?")
        if token.endswith("*"):
            while index < len(remaining) and remaining[index] == role:
                index += 1
        elif index < len(remaining) and remaining[index] == role:
            index += 1
        elif not token.endswith("?"):
            raise ValueError("Missing required CTree child role: " + role)
    if index != len(remaining):
        raise ValueError("Invalid CTree child order")


def _validate_types(types: dict) -> None:
    for source_id, descriptor in types.items():
        if not source_id.startswith("type:") or type(descriptor) is not dict:
            raise ValueError("Invalid CTree type descriptor")
        digest_text(source_id[5:])
        if type(descriptor.get("display")) is not str:
            raise ValueError("Invalid CTree type display")
        for label, value in descriptor.items():
            if label.endswith("_type_id") and value is not None and (type(value) is not str or value not in types):
                raise ValueError("Dangling CTree type reference")
            if label.endswith("_type_ids") and (type(value) is not list or
                                               any(type(ref) is not str or ref not in types for ref in value)):
                raise ValueError("Dangling CTree type reference")
        if "fields" in descriptor:
            for entry in descriptor["fields"]:
                if entry.get("type_id") is not None and entry["type_id"] not in types:
                    raise ValueError("Dangling CTree field type reference")


def _validate_nodes(document: dict, end: int, entry: int) -> None:
    nodes = table(document["nodes"], MAX_NODES)
    types = table(document["types"], MAX_TYPES)
    _validate_types(types)
    variables = document["local_variables"]
    if type(variables) is not list or len(variables) > MAX_NODES:
        raise ValueError("Invalid CTree variable table")
    for index, variable in enumerate(variables):
        fields(variable, {"argument", "definition_ea", "lvar_index", "name", "size_bytes",
                          "storage", "type_id", "user_name", "user_type"})
        if (type(variable["lvar_index"]) is not int or variable["lvar_index"] != index
                or type(variable["name"]) is not str or type(variable["storage"]) is not dict
                or any(type(variable[flag]) is not bool for flag in ("argument", "user_name", "user_type"))
                or variable["type_id"] is not None and variable["type_id"] not in types):
            raise ValueError("Invalid CTree variable descriptor")
        if variable["definition_ea"] is not None:
            hex_address(variable["definition_ea"])
        if variable["size_bytes"] is not None and (type(variable["size_bytes"]) is not int or variable["size_bytes"] < 0):
            raise ValueError("Invalid CTree variable size")

    root = document["function"]["root_node"]
    if root != "node:root" or root not in nodes:
        raise ValueError("Invalid CTree root")
    for key, node in nodes.items():
        category = node["category"]
        required = {"id", "path", "category", "opcode", "opcode_value", "ea", "label",
                    "children", "attributes", "status"}
        if category == "expression":
            required.add("type_id")
        fields(node, required)
        if (category not in {"statement", "expression"} or not isinstance(node["path"], str)
                or key != node["id"] or key != "node:" + node["path"] or type(node["opcode"]) is not str
                or type(node["opcode_value"]) is not int or type(node["attributes"]) is not dict
                or type(node["status"]) is not str):
            raise ValueError("Invalid CTree node identity")
        if node["ea"] is not None and not entry <= hex_address(node["ea"]) < end:
            raise ValueError("CTree node EA outside the function")
        if node.get("type_id") is not None and node["type_id"] not in types:
            raise ValueError("Dangling CTree expression type")
        if node["opcode"] == "cot_var":
            index = node["attributes"].get("lvar_index")
            if type(index) is not int or not 0 <= index < len(variables):
                raise ValueError("Dangling CTree variable reference")
    if nodes[root]["category"] != "statement":
        raise ValueError("CTree root must be a statement")
    visible = {}
    for key, node in nodes.items():
        known = node["opcode"] in STATEMENTS or node["opcode"] in EXPRESSIONS
        if node["children"] is None and (not known or node["status"] not in {"represented", "partial-type"}):
            visible[key] = {**node, "children": []}
        else:
            visible[key] = node
    validate_tree(visible, root)
    for key, node in visible.items():
        profile = STATEMENTS if node["category"] == "statement" else EXPRESSIONS
        other = EXPRESSIONS if profile is STATEMENTS else STATEMENTS
        opcode = node["opcode"]
        if opcode in other:
            raise ValueError("CTree opcode/category mismatch")
        if opcode in profile and node["status"] in {"represented", "partial-type"}:
            _role_sequence(profile[opcode][1], node["children"])
        for child in node["children"]:
            role, index = child["role"], child["index"]
            if child["id"] != f"{key}/{role}[{index}]":
                raise ValueError("CTree child path contradicts role/index")
            expected_statement = role in {"statement", "body", "then", "else"}
            if opcode in profile and nodes[child["id"]]["category"] != (
                    "statement" if expected_statement else "expression"):
                raise ValueError("CTree child category contradicts its role")
    categories = Counter(node["category"] for node in nodes.values())
    verification = document["verification"]
    actual = {"statements": categories["statement"], "expressions": categories["expression"], "total": len(nodes)}
    if (verification["structural"] != actual
            or document["op_histogram"] != Counter(node["opcode"] for node in nodes.values())
            or verification["opaque_node_count"] != sum(node["status"] == "opaque" for node in nodes.values())
            or verification["diagnostic_count"] != len(document["diagnostics"])):
        raise ValueError("CTree counts do not match contents")


def read_ctree(data: bytes, verified_project: VerifiedProject, expected_export: ExpectedExport) -> ValidatedCTree:
    """Read one pinned export. Unknown opcodes retain their visible subtree."""
    digest_text(expected_export.sha256)
    digest_text(expected_export.fingerprint)
    document = read_record(data)
    if sha256(data).hexdigest() != expected_export.sha256:
        raise ValueError("CTree SHA-256 mismatch")
    fields(document, {"schema_version", "environment", "function", "nodes", "types", "local_variables",
                      "op_histogram", "verification", "diagnostics", "scope", "decompilation",
                      "exported_at_utc", "export_fingerprint", "export_fingerprint_algorithm"})
    if document["schema_version"] != SCHEMA:
        raise ValueError("Unsupported CTree source version")
    environment = document["environment"]
    if (any(environment.get(key) != value for key, value in ENVIRONMENT.items())
            or document["decompilation"] != {"maturity_name": "CMAT_FINAL", "maturity_value": 8}):
        raise ValueError("Unsupported CTree producer, maturity or address domain")
    if environment["input_file_sha256"] != verified_project.function.binary.sha256:
        raise ValueError("CTree binary SHA-256 mismatch")
    if hex_address(environment["ida_image_base_ea"]) != verified_project.image_base:
        raise ValueError("CTree image base mismatch")
    function = document["function"]
    fields(function, {"entry_ea", "end_ea", "name", "root_node"})
    entry, end = hex_address(function["entry_ea"]), hex_address(function["end_ea"])
    if entry != verified_project.image_base + verified_project.function.rva or not entry < end:
        raise ValueError("CTree function address mismatch")
    verified_project.file_offset(entry, end - entry, executable=True)
    if datetime.fromisoformat(document["exported_at_utc"]).utcoffset() != timedelta(0):
        raise ValueError("Expected a UTC CTree export timestamp")
    if (document["export_fingerprint_algorithm"] != "sha256-canonical-ctree-semantic-v2"
            or document["export_fingerprint"] != expected_export.fingerprint
            or export_fingerprint(document) != expected_export.fingerprint):
        raise ValueError("CTree export fingerprint mismatch")
    if type(document["diagnostics"]) is not list:
        raise ValueError("Invalid CTree diagnostics")
    _validate_nodes(document, end, entry)
    return ValidatedCTree(verified_project, expected_export, document)


def _ida_address(ea: str | None) -> dict | None:
    return {"domain": "IDA_EA", "value": ea} if ea is not None else None


def _type_kind(descriptor: dict) -> str:
    kinds = {"is_ptr": "Pointer", "is_array": "Array", "is_func": "Function", "is_udt": "Struct"}
    for flag, kind in kinds.items():
        if descriptor.get(flag):
            return kind
    if any(descriptor.get(flag) for flag in ("is_integral", "is_float", "is_void")):
        return "Primitive"
    return "Unknown"


def build_hir(source: ValidatedCTree) -> HIRFunction:
    """Normalize the F1 profile without importing IDA or retaining SDK objects."""
    document = source.document
    nodes = document["nodes"]
    hir = HIRFunction(source.project.function, source.expected.sha256, source.expected.fingerprint,
                      NORMALIZER, "", {}, {}, {}, "complete")
    ids = {key: hir.identity("node:" + row["category"], key) for key, row in nodes.items()}
    types = {key: hir.identity("type", key) for key in document["types"]}
    variables = {row["lvar_index"]: hir.identity("variable", str(row["lvar_index"]))
                 for row in document["local_variables"]}
    for key, descriptor in document["types"].items():
        refs = {}
        for role, value in descriptor.items():
            if role.endswith("_type_id") and value is not None:
                refs[role] = [types[value]]
            if role.endswith("_type_ids"):
                refs[role] = [types[ref] for ref in value]
        origin = descriptor.get("source")
        hir.types[types[key]] = {
            "source_id": key, "kind": _type_kind(descriptor), "display": descriptor["display"],
            "evidence": {"source": "HEX_RAYS_REPORTED" if origin else "UNKNOWN_SOURCE",
                         "raw_source": origin, "confidence": "reported",
                         "completeness": descriptor.get("structure_status", "unknown")},
            "facts": descriptor, "references": refs,
        }
    for row in document["local_variables"]:
        index = row["lvar_index"]
        hir.variables[variables[index]] = {
            "index": index, "name": row["name"], "role": "parameter" if row["argument"] else "local",
            "storage": row["storage"], "definition_address": _ida_address(row["definition_ea"]),
            "size_bytes": row["size_bytes"], "type_id": types.get(row["type_id"]),
            "user_name": row["user_name"], "user_type": row["user_type"],
        }
    parents = {}
    roles = {}
    for parent in nodes.values():
        for child in parent["children"] or ():
            parents[child["id"]] = parent, child["role"]
            pair = parent["opcode"], child["role"]
            if pair in {("cot_asg", "x"), ("cot_preinc", "x")}:
                roles[child["id"]] = "lvalue"
            if pair == ("cot_ref", "x"):
                roles[child["id"]] = "address_only"
    for key, row in nodes.items():
        category, opcode = row["category"], row["opcode"]
        profile = STATEMENTS if category == "statement" else EXPRESSIONS
        supported = opcode in profile and row["status"] in {"represented", "partial-type"}
        coverage = "represented" if row["status"] == "represented" else "partial"
        attributes = row["attributes"].copy()
        evaluation = {"order": "ordered"}
        if opcode == "cit_for":
            evaluation["roles"] = ["init", "condition", "body", "step", "condition"]
        if opcode == "cot_call":
            evaluation["order"] = "unknown"
            parent, role = parents[key]
            evaluation["result_used"] = parent["opcode"] != "cit_expr" and not (
                parent["opcode"] == "cit_for" and role in {"init", "step"})
            guards = []
            ancestor = key
            while ancestor in parents:
                parent, role = parents[ancestor]
                if ((parent["opcode"] == "cit_if" and role in {"then", "else"})
                        or (parent["opcode"] == "cit_for" and role in {"body", "step"})):
                    condition = next((child["id"] for child in parent["children"] or ()
                                      if child["role"] == "condition"), None)
                    if condition is not None:
                        guards.append({"node": ids[condition], "polarity": role != "else"})
                ancestor = parent["id"]
            evaluation["guards"] = list(reversed(guards))
        if opcode == "cot_var":
            attributes["variable"] = variables[attributes["lvar_index"]]
        if opcode == "cot_asg":
            evaluation.update({"order": "assignment", "result": "assigned_value"})
        if opcode == "cot_preinc":
            evaluation["result"] = "updated_value"
        kind = profile[opcode][0] if supported else "Opaque"
        if kind == "ArrayAccess":
            attributes.update({"index_unit": "element", "element_size_bytes": None, "offset_scale": None})
        if kind == "Opaque":
            missing = ("TRUNCATED" if "truncat" in row["status"] else
                       "UNKNOWN_CHILDREN" if row["children"] is None or row["status"] != "represented"
                       else "KNOWN_CHILDREN")
            attributes = {"raw": row, "opcode": opcode, "opcode_value": row["opcode_value"],
                          "reason": "Opcode or source coverage outside the supported profile",
                          "subtree": missing, "footprint": {"read": True, "write": True, "control": True}}
            coverage = "unsupported"
        elif kind in {"Unary", "Binary"}:
            attributes["operator"] = {"cot_preinc": "preincrement", "cot_lnot": "logical_not",
                                      "cot_ne": "not_equal"}[opcode]
        hir.nodes[ids[key]] = {
            "kind": kind, "category": category, "source_id": key, "address": _ida_address(row["ea"]),
            "children": [{**child, "id": ids[child["id"]]} for child in row["children"] or ()],
            "type_id": types.get(row.get("type_id")), "payload": attributes, "coverage": coverage,
            "evaluation": evaluation, "value_role": "statement" if category == "statement" else roles.get(key, "value"),
        }
    partial = document["diagnostics"] or any(row["coverage"] != "represented" for row in hir.nodes.values())
    return replace(hir, entry=ids[document["function"]["root_node"]],
                   assessment="partial" if partial else "complete")
