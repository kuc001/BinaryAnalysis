"""Lower the observed structured HIR profile to the common CIR v2 core."""
from dataclasses import dataclass
from typing import Any

from emtaint.ir.canonical.wire_v2 import CIRFunctionV2
from emtaint.ir.hir.model import HIRFunction

LOWERER = "Structured-HIR-CIR-v2-v1"
UNKNOWN = {"kind": "unknown", "bits": None}
BOOLEAN = {"kind": "boolean", "bits": 1}
POINTER = {"kind": "pointer", "bits": None}
FOOTPRINT = {"read": ["*"], "write": ["*"], "clobber": ["*"], "unknown": True}
MEMORY_READ = {"read": ["*"], "write": [], "clobber": [], "unknown": False}
MEMORY_WRITE = {"read": [], "write": ["*"], "clobber": [], "unknown": False}
MEMORY_UPDATE = {"read": ["*"], "write": ["*"], "clobber": [], "unknown": False}


@dataclass(frozen=True)
class Lowering:
    """Common CIR plus normalization evidence for the provenance producer."""
    cir: CIRFunctionV2
    block_sources: dict[str, str]


class _Builder:
    def __init__(self, hir: HIRFunction, evidence: dict[str, dict]) -> None:
        self.hir = hir
        self.evidence = evidence
        self.blocks: dict[str, dict] = {}
        self.block_sources: dict[str, str] = {}
        self.definitions: dict[str, dict] = {}
        self.diagnostics = ["Call side effects and ABI are unknown",
                            "Address scales and memory-object identities require additional evidence"]
        self.entry = self.new_block("entry", hir.entry, source=True)

    def new_block(self, role: str, node: str, *, source: bool = False) -> str:
        local_id = f"{role}:{node}"
        if local_id in self.blocks:
            raise ValueError("Duplicate structured block")
        anchor = self.hir.nodes[node]["address"]
        self.blocks[local_id] = {
            "origin_kind": "source" if source else "synthetic",
            "anchor_domain": anchor["domain"] if anchor else None,
            "anchor_address": int(anchor["value"], 16) if anchor else None,
            "inputs": [], "parameters": [], "effects": [],
        }
        self.block_sources[local_id] = node
        return local_id

    def value_type(self, node: dict) -> dict:
        record = self.hir.types.get(node["type_id"], {})
        kind = record.get("kind")
        facts = record.get("facts", {})
        size = facts.get("size_bytes")
        if kind == "Pointer":
            return POINTER
        if kind == "Primitive" and type(size) is int and size > 0 and facts.get("is_integral"):
            return {"kind": "integer", "bits": size * 8}
        return UNKNOWN

    def variable_type(self, variable: str) -> dict:
        return self.value_type(self.hir.variables[variable])

    def definition(self, key: str, kind: str, value_type: dict, variable: str | None = None) -> str:
        self.definitions[key] = {"kind": kind, "type": value_type, "variable": variable}
        return key

    def effect(self, block: str, node: str, op: str, operands: tuple = (), *,
               result: dict | None = None, variable: str | None = None,
               data: dict | None = None, sources: tuple[str, ...] = (),
               instruction: str | None = None) -> str | None:
        effects = self.blocks[block]["effects"]
        key = f"{block}/effect/{len(effects)}"
        outputs = [] if result is None else [
            self.definition(f"{key}/result/0", "unknown" if op == "unknown" else "effect", result, variable),
        ]
        uses = []
        counts: dict[str, int] = {}
        for role, definition in operands:
            ordinal = counts.get(role, 0)
            counts[role] = ordinal + 1
            uses.append({"id": f"{key}/use/{role}/{ordinal}", "definition": definition,
                         "role": role, "ordinal": ordinal})
        effects.append({"id": key, "op": op, "uses": uses, "outputs": outputs, "data": data or {},
                        "provenance": list(dict.fromkeys((node, *sources))),
                        "instruction_origin": instruction})
        return outputs[0] if outputs else None

    def children(self, node: str) -> dict[str, str]:
        return {child["role"]: child["id"] for child in self.hir.nodes[node]["children"]}

    def jump(self, block: str, node: str, target: str) -> None:
        self.effect(block, node, "jump", data={"target": target})

    def condition(self, block: str, node: str, env: dict[str, str]) -> str:
        value = self.expression(block, node, env)
        if self.definitions[value]["type"] == BOOLEAN:
            return value
        return self.effect(block, node, "nonzero", (("operand", value),), result=BOOLEAN)

    def unknown(self, block: str, node: str, reason: str, operands: tuple = (),
                *, value_type: dict = UNKNOWN, footprint: dict | None = None,
                may_change_control: bool = False) -> str:
        self.diagnostics.append(reason)
        return self.effect(block, node, "unknown", operands, result=value_type,
                           data={"reason": reason, "footprint": footprint,
                                 "may_change_control": may_change_control})

    def opaque(self, block: str, key: str) -> str:
        payload = self.hir.nodes[key]["payload"]
        footprint = payload["footprint"]
        # Opaque code may clobber unmodeled state even if its source record
        # separately bounds its memory and control effects.
        return self.unknown(block, key, payload["reason"], footprint={
            "read": ["*"] if footprint["read"] else [],
            "write": ["*"] if footprint["write"] else [],
            "clobber": ["*"], "unknown": False,
        }, may_change_control=footprint["control"])

    def has_opaque_control(self, key: str) -> bool:
        pending = [key]
        while pending:
            node = self.hir.nodes[pending.pop()]
            if node["kind"] == "Opaque" and node["payload"]["footprint"]["control"]:
                return True
            pending.extend(child["id"] for child in node["children"])
        return False

    def _source_use(self, block: str, key: str, variable: str, env: dict) -> str:
        type_record = self.hir.types.get(self.hir.variables[variable]["type_id"], {})
        if type_record.get("kind") == "Array":
            return self.effect(block, key, "symbolic_address", result=POINTER,
                               data={"variable": variable, "object": None, "byte_offset": None,
                                     "reason": "Array storage is an unverified source location"})
        if variable in env:
            return self.effect(block, key, "copy", (("source", env[variable]),),
                               result=self.variable_type(variable), variable=variable)
        return self.unknown(block, key, "Local has no reaching definition",
                            value_type=self.variable_type(variable))

    def _address(self, block: str, key: str, env: dict) -> str:
        node = self.hir.nodes[key]
        children = self.children(key)
        if node["kind"] == "ArrayAccess":
            base = self.expression(block, children["x"], env)
            index = self.expression(block, children["y"], env)
            return self.effect(block, key, "symbolic_address", (("base", base), ("index", index)),
                               result=POINTER, data={"index_unit": node["payload"]["index_unit"],
                                                    "element_size_bytes": None, "offset_scale": None,
                                                    "byte_offset": None, "object": None})
        if node["kind"] == "VariableRef":
            return self.effect(block, key, "symbolic_address", result=POINTER,
                               data={"variable": node["payload"]["variable"], "object": None})
        return self.unknown(block, key, "Unsupported lvalue address", value_type=POINTER,
                            footprint=FOOTPRINT, may_change_control=self.has_opaque_control(key))

    def expression(self, block: str, key: str, env: dict[str, str]) -> str:
        node = self.hir.nodes[key]
        kind, data = node["kind"], node["payload"]
        children = self.children(key)
        match kind:
            case "Constant":
                if "numeric_value_hex" in data:
                    return self.effect(block, key, "constant", result=self.value_type(node),
                                       data={"value": int(data["numeric_value_hex"], 16)})
                return self.effect(block, key, "constant", result=POINTER,
                                   data={"literal": data.get("string"), "object": None, "partial": True})
            case "VariableRef":
                return self._source_use(block, key, data["variable"], env)
            case "AddressedObjectRef":
                address = data.get("object_ea")
                if address is None:
                    return self.unknown(block, key, "Missing source object address", value_type=POINTER)
                return self.effect(block, key, "object_address", result=POINTER,
                                   data={"candidate": {"domain": "IDA_EA", "value": address},
                                         "object": None, "partial": True})
            case "HelperRef":
                return self.unknown(block, key, "Helper has no verified callable address", value_type=POINTER)
            case "Assign":
                right = self.expression(block, children["y"], env)
                target = self.hir.nodes[children["x"]]
                if target["kind"] != "VariableRef":
                    if target["kind"] == "Dereference":
                        pointer = self.children(children["x"])["x"]
                        if self.hir.nodes[pointer]["kind"] in {"VariableRef", "Constant", "AddressedObjectRef"}:
                            address = self.expression(block, pointer, env)
                            return self.unknown(block, key, "Unverified indirect store",
                                                (("address", address), ("value", right)), footprint=MEMORY_WRITE)
                    return self.unknown(block, key, "Unsupported assignment target",
                                        (("value", right),), footprint=FOOTPRINT,
                                        may_change_control=self.has_opaque_control(children["x"]))
                variable = target["payload"]["variable"]
                result = self.effect(block, key, "copy", (("value", right),), result=self.variable_type(variable),
                                     variable=variable, sources=(children["x"],))
                env[variable] = result
                return result
            case "Unary":
                value = self.expression(block, children["x"], env)
                if data["operator"] == "logical_not":
                    return self.effect(block, key, "is_zero", (("operand", value),), result=BOOLEAN)
                target = self.hir.nodes[children["x"]]
                if target["kind"] != "VariableRef":
                    return self.unknown(block, key, "Unsupported preincrement target",
                                        (("operand", value),), footprint=MEMORY_UPDATE)
                variable = target["payload"]["variable"]
                value_type = self.variable_type(variable)
                if value_type["kind"] != "integer":
                    updated = self.unknown(block, key, "Unknown preincrement width", (("operand", value),),
                                           value_type=value_type)
                else:
                    one = self.effect(block, key, "constant", result=value_type, data={"value": 1})
                    updated = self.effect(block, key, "add", (("left", value), ("right", one)),
                                          result=value_type, variable=variable, sources=(children["x"],),
                                          data={"overflow": "unknown", "width_source": "reported_type",
                                                "partial": True})
                env[variable] = updated
                return updated
            case "Binary":
                left = self.expression(block, children["x"], env)
                right = self.expression(block, children["y"], env)
                return self.effect(block, key, "compare_ne", (("left", left), ("right", right)), result=BOOLEAN)
            case "Cast":
                child = self.expression(block, children["x"], env)
                return self.unknown(block, key, "Cast ABI and conversion width are unverified",
                                    (("operand", child),), value_type=self.value_type(node))
            case "AddressOf":
                address = self._address(block, children["x"], env)
                return self.effect(block, key, "copy", (("address", address),), result=POINTER)
            case "ArrayAccess":
                address = self._address(block, key, env)
                return self.unknown(block, key, "Unverified array access width or layout",
                                    (("address", address),), footprint=MEMORY_READ)
            case "Dereference":
                address = self.expression(block, children["x"], env)
                width = data.get("pointer_access_size_bytes")
                witness = self.evidence.get(key, {})
                if type(width) is not int or width < 1:
                    return self.unknown(block, key, "Missing dereference width", (("address", address),),
                                        footprint=MEMORY_READ)
                if self.definitions[address]["type"]["kind"] != "pointer":
                    return self.unknown(block, key, "Dereference address type is unknown",
                                        (("address", address),), footprint=MEMORY_READ)
                return self.effect(block, key, "read_memory", (("address", address),),
                                   result={"kind": "integer", "bits": width * 8},
                                   data={"width_bytes": width, "object": None, "partial": True,
                                         "width_source": "verified_instruction" if witness else "reported_access"},
                                   instruction=witness.get("instructions", [None])[0])
            case "Call":
                return self.call(block, key, env)
            case "Opaque":
                return self.opaque(block, key)
            case _:
                raise ValueError("Unexpected HIR expression: " + kind)

    def call(self, block: str, key: str, env: dict) -> str | None:
        node = self.hir.nodes[key]
        children = node["children"]
        pure_arguments = {"VariableRef", "Constant", "AddressedObjectRef", "HelperRef"}
        # For this profile only pure operands can be read in positional order.
        if any(self.hir.nodes[child["id"]]["kind"] not in pure_arguments for child in children):
            return self.unknown(block, key, "Call operand evaluation ordering is unsupported",
                                footprint=FOOTPRINT, may_change_control=self.has_opaque_control(key))
        values = [(child["role"], self.expression(block, child["id"], env)) for child in children]
        callee = self.hir.nodes[children[0]["id"]]["payload"]
        witness = self.evidence.get(key, {})
        if "branch_target" in witness:
            target = {"kind": "direct_address", "domain": "LINKED_VA", "address": witness["branch_target"]}
        elif callee.get("object_ea"):
            target = {"kind": "candidate", "domain": "IDA_EA", "address": callee["object_ea"]}
        else:
            target = {"kind": "unknown", "reason": "No resolved target"}
        return self.effect(
            block, key, "call", tuple(values), result=self.value_type(node) if node["evaluation"]["result_used"] else None,
            data={"target": target, "argument_count": len(children) - 1, "footprint": FOOTPRINT,
                  "abi": None, "evaluation_order": "unknown", "result_used": node["evaluation"]["result_used"],
                  "guard": {"kind": "block_reachability", "block": block}},
            instruction=witness.get("instructions", [None])[0],
        )

    def _phi(self, block: str, variable: str, incoming: dict) -> dict:
        params = self.blocks[block]["parameters"]
        definition = self.definition(f"{block}/phi/{len(params)}", "phi", self.variable_type(variable), variable)
        row = {"definition": definition, "incoming": incoming}
        params.append(row)
        return row

    def _assigned(self, key: str) -> set[str]:
        affected = set()
        pending = [key]
        while pending:
            node_id = pending.pop()
            node = self.hir.nodes[node_id]
            if node["kind"] == "Assign" or node["payload"].get("operator") == "preincrement":
                target = self.hir.nodes[self.children(node_id)["x"]]
                if target["kind"] == "VariableRef":
                    affected.add(target["payload"]["variable"])
            pending.extend(child["id"] for child in node["children"])
        return affected

    def _branch(self, block: str, key: str, condition: str, yes: str, no: str, env: dict[str, str]) -> None:
        witness = self.evidence.get(condition, {})
        guard = self.condition(block, condition, env)
        self.effect(block, key, "branch", (("guard", guard),), data={"true": yes, "false": no},
                    sources=(condition,), instruction=witness.get("branch_instruction"))

    def statement(self, block: str, key: str, env: dict[str, str]) -> str | None:
        node = self.hir.nodes[key]
        kids = self.children(key)
        match node["kind"]:
            case "Block":
                end = block
                for child in node["children"]:
                    if end is None:
                        break
                    end = self.statement(end, child["id"], env)
                return end
            case "ExpressionStatement":
                self.expression(block, kids["expression"], env)
            case "Return":
                operands = (("return", self.expression(block, kids["value"], env)),) if "value" in kids else ()
                self.effect(block, key, "return", operands)
                return None
            case "If":
                return self.lower_if(block, key, env)
            case "For":
                return self.lower_for(block, key, env)
            case "Opaque":
                self.opaque(block, key)
                if node["payload"]["footprint"]["control"]:
                    self.effect(block, key, "unknown_exit", data={"reason": "Unknown statement continuation"})
                    return None
            case _:
                raise ValueError("Unexpected HIR statement kind")
        return block

    def lower_if(self, block: str, key: str, env: dict) -> str | None:
        kids = self.children(key)
        yes, no = self.new_block("then", key), self.new_block("else", key)
        self._branch(block, key, kids["condition"], yes, no, env)
        yes_env, no_env = env.copy(), env.copy()
        yes_end = self.statement(yes, kids["then"], yes_env)
        no_end = self.statement(no, kids["else"], no_env) if "else" in kids else no
        incoming = {end: values for end, values in ((yes_end, yes_env), (no_end, no_env)) if end is not None}
        if not incoming:
            return None
        join = self.new_block("join", key)
        merged = {}
        variables = set().union(*(values.keys() for values in incoming.values()))
        for variable in sorted(variables):
            definitions = {end: values.get(variable) for end, values in incoming.items()}
            for end, definition in list(definitions.items()):
                if definition is None:
                    definitions[end] = self.unknown(end, key, "Variable unavailable on one incoming branch",
                                                    value_type=self.variable_type(variable))
            distinct = set(definitions.values())
            merged[variable] = (next(iter(distinct)) if len(distinct) == 1
                                else self._phi(join, variable, definitions)["definition"])
        for end in incoming:
            self.jump(end, key, join)
        env.clear()
        env.update(merged)
        return join

    def lower_for(self, block: str, key: str, env: dict) -> str:
        kids = self.children(key)
        init = self.new_block("init", key)
        header = self.new_block("header", key)
        body = self.new_block("body", key)
        exit_block = self.new_block("exit", key)
        self.jump(block, key, init)
        self.expression(init, kids["init"], env)
        loop_env = env.copy()
        parameters = {}
        modified = self._assigned(kids["body"]) | self._assigned(kids["step"]) | self._assigned(kids["condition"])
        for variable in sorted(modified):
            initial = env.get(variable)
            if initial is None:
                initial = self.unknown(init, key, "Variable unavailable on loop entry",
                                       value_type=self.variable_type(variable))
            parameters[variable] = self._phi(header, variable, {init: initial})
            loop_env[variable] = parameters[variable]["definition"]
        self.jump(init, key, header)
        self._branch(header, key, kids["condition"], body, exit_block, loop_env)
        body_env = loop_env.copy()
        body_end = self.statement(body, kids["body"], body_env)
        if body_end is not None:
            latch = self.new_block("latch", key)
            self.jump(body_end, key, latch)
            self.expression(latch, kids["step"], body_env)
            self.jump(latch, key, header)
            for variable, parameter in parameters.items():
                parameter["incoming"][latch] = body_env[variable]
        env.clear()
        env.update(loop_env)
        return exit_block

    def build(self) -> Lowering:
        env = {}
        for variable, info in sorted(self.hir.variables.items(), key=lambda item: item[1]["index"]):
            if info["role"] == "parameter":
                inputs = self.blocks[self.entry]["inputs"]
                env[variable] = self.definition(f"{self.entry}/input/{len(inputs)}", "input",
                                                self.variable_type(variable), variable)
                inputs.append(env[variable])
        end = self.statement(self.entry, self.hir.entry, env)
        if end is not None:
            self.effect(end, self.hir.entry, "unknown_exit", data={"reason": "No explicit return"})
        return Lowering(CIRFunctionV2(self.hir.function, LOWERER, self.entry, self.blocks,
                                       self.definitions, "partial", list(dict.fromkeys(self.diagnostics))),
                        self.block_sources)


def lower_hir(hir: HIRFunction, evidence: dict[str, dict[str, Any]]) -> Lowering:
    """Lower a validated HIR body using separately established instruction evidence."""
    return _Builder(hir, evidence).build()
