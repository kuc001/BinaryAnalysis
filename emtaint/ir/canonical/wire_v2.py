"""Common CIR v2 interchange for typed definitions, ordered effects and shared CFG."""
from dataclasses import asdict, dataclass
from hashlib import sha256
from typing import Any

from emtaint.core.identity import BinaryId, FunctionId, ProgramBlockId
from emtaint.core.program import Completeness
from emtaint.core.wire_json import canonical_json, fields, read_record, table
from emtaint.graph.program_graphs import ControlFlowGraph, FlowEdge, FlowKind

SCHEMA = "CIR-Wire-v2"
CFG_SCHEMA = "Program-CFG-v1"
OPS = {
    "constant", "object_address", "symbolic_address", "copy", "cast", "unknown", "havoc",
    "add", "compare_ne", "is_zero", "nonzero", "read_memory", "write_memory", "call",
    "branch", "jump", "return", "unknown_exit",
}
TERMINATORS = {"branch", "jump", "return", "unknown_exit"}
TARGETS = {"direct_address", "resolved_function", "candidate", "unknown"}
TYPE_KINDS = {"integer", "boolean", "pointer", "memory", "unknown"}


@dataclass(frozen=True)
class CIRFunctionV2:
    """Common CIR body. References outside this body bind its canonical digest."""

    function: FunctionId
    producer: str
    entry: str
    blocks: dict[str, dict[str, Any]]
    definitions: dict[str, dict[str, Any]]
    completeness: str
    diagnostics: list[str]

    @property
    def body_digest(self) -> str:
        return sha256(_body(self)).hexdigest()

    def scoped_reference(self, local_id: str) -> dict:
        """Bind a local effect, definition, or use ID to this body revision."""
        return {"schema": SCHEMA, "function": self.function.token,
                "body_sha256": self.body_digest, "local_id": local_id}


def _body(cir: CIRFunctionV2) -> bytes:
    return canonical_json({"schema_version": SCHEMA, **asdict(cir)})


def _destinations(terminal: dict) -> tuple[tuple[str, FlowKind], ...]:
    data = terminal["data"]
    if terminal["op"] == "branch":
        return ((data["true"], FlowKind.TRUE), (data["false"], FlowKind.FALSE))
    if terminal["op"] == "jump":
        return ((data["target"], FlowKind.JUMP),)
    return ()


def graph(cir: CIRFunctionV2) -> ControlFlowGraph:
    """Project the body to the shared CFG without assuming machine addresses."""
    blocks = {key: ProgramBlockId(cir.function, key, row["origin_kind"],
                                 row["anchor_domain"], row["anchor_address"])
              for key, row in cir.blocks.items()}
    edges = frozenset(FlowEdge(blocks[key], blocks[target], kind,
                               row["effects"][-1]["uses"][0]["id"] if kind in {FlowKind.TRUE, FlowKind.FALSE} else "")
                      for key, row in cir.blocks.items()
                      for target, kind in _destinations(row["effects"][-1]))
    exits = frozenset(blocks[key] for key, row in cir.blocks.items()
                      if row["effects"][-1]["op"] in {"return", "unknown_exit"})
    status = Completeness.COMPLETE if cir.completeness == "complete" else Completeness.INCOMPLETE
    return ControlFlowGraph(cir.function, frozenset(blocks.values()), edges, blocks[cir.entry], exits,
                            status, "Structured CIR control flow; see CIR assessment")


def cfg_record(cir: CIRFunctionV2) -> dict:
    """Represent a shared CFG with guard Use IDs and explicit block identities."""
    cfg = graph(cir)
    return {
        "schema_version": CFG_SCHEMA, "entry": cfg.entry.local_id,
        "exits": sorted(node.local_id for node in cfg.exits), "status": cfg.status.value,
        "nodes": {node.local_id: {"origin_kind": node.origin_kind, "synthetic": node.synthetic,
                                  "anchor_domain": node.anchor_domain, "anchor_address": node.anchor_address}
                  for node in cfg.nodes},
        "edges": sorted([[edge.source.local_id, edge.target.local_id, edge.kind.value, edge.label]
                         for edge in cfg.edges]),
    }


def phi_use_id(definition_id: str, predecessor: str) -> str:
    """Identify an incoming use by its predecessor rather than list position."""
    return f"{definition_id}/incoming/{predecessor}"


def _validate(cir: CIRFunctionV2) -> None:
    blocks = table(cir.blocks, 100_000)
    definitions = table(cir.definitions, 500_000)
    if (cir.entry not in blocks or cir.completeness not in {"complete", "partial", "unsupported"}
            or type(cir.producer) is not str or not cir.producer
            or type(cir.diagnostics) is not list or any(type(reason) is not str for reason in cir.diagnostics)):
        raise ValueError("Invalid CIR header")
    producers: dict[str, tuple[str, int, str]] = {}
    uses: list[tuple[str, int, str]] = []
    predecessors: dict[str, set[str]] = {block: set() for block in blocks}
    successors: dict[str, set[str]] = {block: set() for block in blocks}
    phi_checks = []
    incomplete = False

    def define(definition: str, block: str, ordinal: int, origin: str) -> None:
        if definition not in definitions or definition in producers:
            raise ValueError("Missing or multiply produced CIR definition")
        producers[definition] = block, ordinal, origin

    for block, row in blocks.items():
        fields(row, {"origin_kind", "anchor_domain", "anchor_address", "inputs", "parameters", "effects"})
        ProgramBlockId(cir.function, block, row["origin_kind"], row["anchor_domain"], row["anchor_address"])
        if any(type(row[name]) is not list for name in ("inputs", "parameters", "effects")):
            raise ValueError("Invalid CIR block tables")
        for ordinal, definition in enumerate(row["inputs"]):
            if block != cir.entry or definition != f"{block}/input/{ordinal}":
                raise ValueError("Invalid CIR input definition")
            define(definition, block, -1, "input")
        for ordinal, parameter in enumerate(row["parameters"]):
            fields(parameter, {"definition", "incoming"})
            definition = parameter["definition"]
            if definition != f"{block}/phi/{ordinal}" or type(parameter["incoming"]) is not dict:
                raise ValueError("Invalid CIR block parameter")
            define(definition, block, -1, "phi")
            phi_checks.append((block, parameter))
        effects = row["effects"]
        if not effects or len(effects) > 500_000:
            raise ValueError("CIR block needs a terminator and a bounded effect list")
        for ordinal, effect in enumerate(effects):
            fields(effect, {"id", "op", "uses", "outputs", "data", "instruction_origin", "provenance"})
            effect_id, op = effect["id"], effect["op"]
            if (effect_id != f"{block}/effect/{ordinal}" or op not in OPS
                    or (op in TERMINATORS) != (ordinal == len(effects) - 1)
                    or type(effect["data"]) is not dict
                    or any(type(effect[name]) is not list for name in ("uses", "outputs", "provenance"))
                    or any(type(ref) is not str for ref in effect["provenance"])):
                raise ValueError("Invalid CIR effect ordering or identity")
            effect_data = effect["data"]
            origin = effect["instruction_origin"]
            if origin is not None and (type(origin) is not str or not origin):
                raise ValueError("Invalid instruction evidence reference")
            if op in {"unknown", "havoc", "unknown_exit", "symbolic_address"} or effect_data.get("partial") is True:
                incomplete = True
            role_ordinals: dict[str, int] = {}
            for use in effect["uses"]:
                fields(use, {"id", "definition", "role", "ordinal"})
                role = use["role"]
                if type(role) is not str or not role or "/" in role:
                    raise ValueError("Invalid use role")
                index = role_ordinals.get(role, 0)
                if (type(use["ordinal"]) is not int or use["ordinal"] != index
                        or use["id"] != f"{effect_id}/use/{role}/{index}"):
                    raise ValueError("Invalid CIR use identity")
                role_ordinals[role] = index + 1
                uses.append((block, ordinal, use["definition"]))
            for index, definition in enumerate(effect["outputs"]):
                if definition != f"{effect_id}/result/{index}":
                    raise ValueError("Invalid CIR effect output identity")
                define(definition, block, ordinal, "unknown" if op == "unknown" else "effect")
            if op == "branch":
                if len(effect["uses"]) != 1 or effect["uses"][0]["role"] != "guard":
                    raise ValueError("Branch requires one guard")
                guard = definitions.get(effect["uses"][0]["definition"], {})
                if guard.get("type", {}).get("kind") != "boolean":
                    raise ValueError("Branch guard requires a Boolean definition")
            if op == "call":
                target = effect_data.get("target")
                if (type(target) is not dict or target.get("kind") not in TARGETS
                        or effect_data.get("argument_count") != role_ordinals.get("argument", 0)):
                    raise ValueError("Invalid call target or argument count")
                target_kind = target["kind"]
                if target_kind in {"direct_address", "candidate"} and (
                        target.get("domain") not in {"LINKED_VA", "IDA_EA", "RVA", "RUNTIME_VA"}
                        or type(target.get("address")) not in {str, int}):
                    raise ValueError("Missing call target address evidence")
                if target_kind == "resolved_function" and not target.get("function"):
                    raise ValueError("Missing resolved function identity")
                if len(effect["uses"]) != role_ordinals.get("argument", 0) + 1 or role_ordinals.get("callee") != 1:
                    raise ValueError("Invalid call use roles")
                if effect_data.get("guard") != {"kind": "block_reachability", "block": block}:
                    raise ValueError("Invalid call guard")
                footprint = effect_data.get("footprint")
                if type(footprint) is not dict or type(footprint.get("unknown")) is not bool:
                    raise ValueError("Missing call effects")
                if footprint["unknown"]:
                    if any(footprint.get(role) != ["*"] for role in ("read", "write", "clobber")):
                        raise ValueError("Unknown call effects require a conservative footprint")
                    incomplete = True
            if op in {"read_memory", "write_memory"}:
                width = effect_data.get("width_bytes")
                required = {"address": 1} if op == "read_memory" else {"address": 1, "value": 1}
                if type(width) is not int or width < 1 or role_ordinals != required:
                    raise ValueError("Memory effect requires a byte width and typed operand roles")
                operands = {use["role"]: definitions.get(use["definition"], {}).get("type", {})
                            for use in effect["uses"]}
                if operands["address"].get("kind") != "pointer":
                    raise ValueError("Memory address operand requires a pointer")
                if op == "read_memory":
                    if len(effect["outputs"]) != 1 or definitions[effect["outputs"][0]]["type"]["bits"] != width * 8:
                        raise ValueError("Memory read output must match the byte width")
                elif operands["value"].get("bits") != width * 8:
                    raise ValueError("Memory write operand must match the byte width")
        for target, _ in _destinations(effects[-1]):
            if target not in blocks:
                raise ValueError("Dangling CIR control edge")
            predecessors[target].add(block)
            successors[block].add(target)

    if set(producers) != set(definitions) or predecessors[cir.entry]:
        raise ValueError("Invalid CIR definition or entry table")
    for definition, row in definitions.items():
        fields(row, {"kind", "type", "variable"})
        fields(row["type"], {"kind", "bits"})
        kind, bits = row["type"]["kind"], row["type"]["bits"]
        if (row["kind"] != producers[definition][2] or kind not in TYPE_KINDS
                or (bits is not None and (type(bits) is not int or bits < 1))
                or (kind == "boolean" and bits != 1)
                or (row["variable"] is not None and type(row["variable"]) is not str)):
            raise ValueError("Invalid typed CIR definition")
    if incomplete and cir.completeness == "complete":
        raise ValueError("Complete CIR cannot contain incomplete effects")
    # Uses from an incoming parameter are evaluated on the predecessor edge.
    for block, parameter in phi_checks:
        incoming = parameter["incoming"]
        if not incoming or set(incoming) != predecessors[block]:
            raise ValueError("Block parameter must cover exactly the predecessors")
        for predecessor, definition in incoming.items():
            if definition not in definitions or definitions[definition]["type"] != definitions[parameter["definition"]]["type"]:
                raise ValueError("Invalid phi incoming definition type")
            uses.append((predecessor, len(blocks[predecessor]["effects"]), definition))

    reachable = set()
    pending = [cir.entry]
    while pending:
        block = pending.pop()
        if block not in reachable:
            reachable.add(block)
            pending.extend(successors[block] - reachable)
    if reachable != set(blocks):
        raise ValueError("Unreachable CIR blocks")
    # Check domination using only the definition blocks needed by cross-block
    # uses. Removing a definition block must make the use block unreachable.
    cross_uses: dict[str, set[str]] = {}
    for block, ordinal, definition in uses:
        if definition not in producers:
            raise ValueError("Dangling CIR use")
        producer, position, _ = producers[definition]
        if producer == block and position >= ordinal:
            raise ValueError("CIR use precedes its definition")
        if producer not in {block, cir.entry}:
            cross_uses.setdefault(producer, set()).add(block)
    budget = 2_000_000
    for producer, targets in cross_uses.items():
        seen = {producer}
        pending = [cir.entry]
        while pending:
            block = pending.pop()
            if block in seen:
                continue
            seen.add(block)
            budget -= 1 + len(successors[block])
            if budget < 0:
                raise ValueError("CIR dominance verification budget exhausted")
            if block in targets:
                raise ValueError("CIR definition does not dominate its use")
            pending.extend(successors[block] - seen)


def encode_cir(cir: CIRFunctionV2) -> bytes:
    """Validate and serialize a Common CIR v2 body."""
    _validate(cir)
    return _body(cir)


def decode_cir(data: bytes, expected: FunctionId | None = None) -> CIRFunctionV2:
    """Read Common CIR v2 using explicit version dispatch."""
    record = read_record(data)
    if record.pop("schema_version", None) != SCHEMA:
        raise ValueError("Unsupported CIR wire version")
    fields(record, set(CIRFunctionV2.__dataclass_fields__))
    function = record["function"]
    fields(function, {"binary", "rva"})
    fields(function["binary"], {"sha256"})
    record["function"] = FunctionId(BinaryId(function["binary"]["sha256"]), function["rva"])
    cir = CIRFunctionV2(**record)
    if expected is not None and cir.function != expected:
        raise ValueError("CIR function identity mismatch")
    _validate(cir)
    return cir
