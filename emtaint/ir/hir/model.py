"""Frontend-independent HIR wire records for structured source semantics."""
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any

from emtaint.core.identity import BinaryId, FunctionId
from emtaint.core.wire_json import canonical_json, digest_text, fields, hex_address, read_record, table

SCHEMA = "HIR-Wire-v1"
MAX_NODES = 100_000
MAX_DEPTH = 300
MAX_TYPES = 20_000
TYPE_SOURCES = frozenset({
    "HEX_RAYS_REPORTED", "DECOMPILER_REPORTED", "USER_TYPE_ANNOTATION",
    "DWARF", "COMPILER_EVIDENCE", "UNKNOWN_SOURCE",
})
TYPE_KINDS = frozenset({"Primitive", "Pointer", "Array", "Function", "Struct", "Union", "Unknown"})
KINDS = frozenset({
    "Block", "ExpressionStatement", "Assign", "If", "For", "Return", "VariableRef", "Constant",
    "HelperRef", "AddressedObjectRef", "Call", "Cast", "AddressOf", "Dereference", "ArrayAccess",
    "Binary", "Unary", "Opaque",
})


def validate_tree(nodes: dict, root: str) -> dict[str, int]:
    """Validate a rooted ordered tree and return its per-node depths."""
    stack = [(root, 0)]
    seen = {}
    while stack:
        node_id, depth = stack.pop()
        if depth > MAX_DEPTH or node_id not in nodes or node_id in seen:
            raise ValueError("Invalid, shared, cyclic or over-depth tree reference")
        seen[node_id] = depth
        children = nodes[node_id]["children"]
        if type(children) is not list:
            raise ValueError("Children must be ordered")
        next_index: dict[str, int] = {}
        for child in children:
            fields(child, {"id", "role", "index"})
            role = child["role"]
            if (type(role) is not str or not role or type(child["id"]) is not str
                    or type(child["index"]) is not int or child["index"] != next_index.get(role, 0)):
                raise ValueError("Invalid child role or ordinal")
            next_index[role] = child["index"] + 1
            stack.append((child["id"], depth + 1))
    if seen.keys() != nodes.keys():
        raise ValueError("Unreachable tree nodes")
    return seen


@dataclass(frozen=True)
class HIRFunction:
    """One typed, revision-bound function and its pure interchange tables."""

    function: FunctionId
    source_sha256: str
    export_fingerprint: str
    normalizer: str
    entry: str
    nodes: dict[str, dict[str, Any]]
    variables: dict[str, dict[str, Any]]
    types: dict[str, dict[str, Any]]
    assessment: str

    def identity(self, category: str, source_id: str) -> str:
        """Derive a local ID from the function, export, producer and source identity."""
        return sha256(canonical_json([
            self.function.token, self.export_fingerprint, self.normalizer, category, source_id,
        ])).hexdigest()


def _validate(hir: HIRFunction) -> None:
    digest_text(hir.source_sha256)
    digest_text(hir.export_fingerprint)
    if type(hir.normalizer) is not str or not hir.normalizer or hir.assessment not in {"complete", "partial"}:
        raise ValueError("Invalid HIR producer or assessment")
    validate_tree(table(hir.nodes, MAX_NODES), hir.entry)
    table(hir.variables, MAX_NODES)
    table(hir.types, MAX_TYPES)
    seen_sources = set()
    for node_id, node in hir.nodes.items():
        fields(node, {"kind", "source_id", "category", "children", "address", "type_id", "payload",
                      "evaluation", "value_role", "coverage"})
        source_id = node["source_id"]
        category = node["category"]
        if (type(source_id) is not str or category not in {"statement", "expression"}
                or source_id in seen_sources or hir.identity("node:" + category, source_id) != node_id):
            raise ValueError("Invalid HIR source identity")
        seen_sources.add(source_id)
        if node["kind"] not in KINDS or node["coverage"] not in {"represented", "partial", "unsupported"}:
            raise ValueError("Invalid HIR node kind or coverage")
        if node["address"] is not None:
            fields(node["address"], {"domain", "value"})
            if node["address"]["domain"] not in {"IDA_EA", "LINKED_VA", "RVA", "FILE_OFFSET", "RUNTIME_VA"}:
                raise ValueError("Invalid HIR address domain")
            hex_address(node["address"]["value"])
        if node["type_id"] is not None and node["type_id"] not in hir.types:
            raise ValueError("Dangling HIR type")
        if type(node["payload"]) is not dict or type(node["evaluation"]) is not dict:
            raise ValueError("Invalid HIR payload or evaluation")
        if node["value_role"] not in {"value", "lvalue", "address_only", "statement"}:
            raise ValueError("Invalid HIR value role")
        if node["kind"] == "VariableRef" and node["payload"].get("variable") not in hir.variables:
            raise ValueError("Dangling HIR variable")
        if node["kind"] == "Call":
            evaluation = node["evaluation"]
            fields(evaluation, {"order", "result_used", "guards"})
            if (evaluation["order"] not in {"unknown", "ordered"}
                    or type(evaluation["result_used"]) is not bool
                    or type(evaluation["guards"]) is not list):
                raise ValueError("Invalid call evaluation")
            for guard in evaluation["guards"]:
                fields(guard, {"node", "polarity"})
                if guard["node"] not in hir.nodes or type(guard["polarity"]) is not bool:
                    raise ValueError("Invalid call guard reference")
        if node["kind"] == "Opaque":
            fields(node["payload"], {"raw", "opcode", "opcode_value", "reason", "subtree", "footprint"})
            if not node["payload"]["reason"] or node["payload"]["subtree"] not in {
                "KNOWN_CHILDREN", "UNKNOWN_CHILDREN", "TRUNCATED",
            } or node["coverage"] != "unsupported":
                raise ValueError("Invalid Opaque coverage")
    seen_indices = set()
    for variable_id, variable in hir.variables.items():
        fields(variable, {"index", "name", "role", "storage", "definition_address", "size_bytes",
                          "type_id", "user_name", "user_type"})
        index = variable["index"]
        if (type(index) is not int or index < 0 or index in seen_indices
                or variable_id != hir.identity("variable", str(index))
                or variable["role"] not in {"parameter", "local"}
                or (variable["type_id"] is not None and variable["type_id"] not in hir.types)):
            raise ValueError("Invalid HIR variable")
        seen_indices.add(index)
    for type_id, record in hir.types.items():
        fields(record, {"source_id", "kind", "display", "evidence", "facts", "references"})
        if (type_id != hir.identity("type", record["source_id"]) or record["kind"] not in TYPE_KINDS
                or record["evidence"].get("source") not in TYPE_SOURCES):
            raise ValueError("Invalid HIR type evidence")
        for references in record["references"].values():
            if type(references) is not list or any(reference not in hir.types for reference in references):
                raise ValueError("Dangling HIR structural type reference")
    if hir.assessment == "complete" and any(n["coverage"] != "represented" for n in hir.nodes.values()):
        raise ValueError("Complete HIR contains partial nodes")


def encode_hir(hir: HIRFunction) -> bytes:
    """Validate and encode a HIR function as canonical UTF-8 JSON."""
    _validate(hir)
    return canonical_json({"schema_version": SCHEMA, **asdict(hir)})


def decode_hir(data: bytes, expected_identity: FunctionId | None = None) -> HIRFunction:
    """Read HIR without importing a frontend or the source binary."""
    record = read_record(data)
    if record.pop("schema_version", None) != SCHEMA:
        raise ValueError("Unsupported HIR wire version")
    fields(record, set(HIRFunction.__dataclass_fields__))
    function = record["function"]
    fields(function, {"binary", "rva"})
    fields(function["binary"], {"sha256"})
    record["function"] = FunctionId(BinaryId(function["binary"]["sha256"]), function["rva"])
    hir = HIRFunction(**record)
    _validate(hir)
    if expected_identity is not None and hir.function != expected_identity:
        raise ValueError("HIR function identity mismatch")
    return hir
