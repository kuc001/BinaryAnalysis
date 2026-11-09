"""Bounded read-only inspectors for CIR values, SSE DAGs, and demand results."""

from __future__ import annotations

from typing import Any
from dataclasses import asdict, is_dataclass
import json
from pathlib import Path

from emtaint.core.contracts import SymbolicExprId, ValueRef
from emtaint.memory.state import SymbolicOp

from .provenance import ProvenanceIndex


def _type_name(value_type: object) -> str:
    """Render one ValueType without exposing its verbose dataclass repr."""

    kind = value_type.kind.value
    signedness = value_type.signedness.value
    space = (
        " @" + value_type.address_space
        if value_type.address_space is not None
        else ""
    )
    return f"{kind}{value_type.bits} {signedness}{space}"


class AnalysisDebugInspector:
    """Read analysis state without issuing memory, alias, or solver queries."""

    def __init__(
        self,
        provenance: ProvenanceIndex | None = None,
        *,
        engine: object | None = None,
        demand: object | None = None,
    ) -> None:
        self.provenance = provenance
        self.engine = engine
        self.demand = demand

    @classmethod
    def from_demand(cls, demand: object) -> "AnalysisDebugInspector":
        """Create a lazy live inspector around an existing demand object."""

        engine = demand.port.engine
        provenance = getattr(engine, 'debug_provenance', None)
        if provenance is None:
            provenance = ProvenanceIndex.for_function_with_architecture(
                demand.function, engine.origins, engine.architecture
            )
        return cls(provenance, engine=engine, demand=demand)

    def explain_value(self, value: ValueRef | str, *, max_depth: int = 5,
                      max_nodes: int = 100, summary: bool = False) -> str:
        """Explain recorded CIR/VEX/instruction provenance without running analysis."""

        value_id = value.id if isinstance(value, ValueRef) else value
        if self.provenance is None:
            return (
                f"Value {value_id}\n"
                "Unavailable: no CIR provenance index is attached."
            )
        declared = self.provenance.value(value_id)
        if declared is None:
            return (
                f"Value {value_id}\n"
                "Unavailable: value is not declared by the indexed CIR module."
            )
        lines = [f"VALUE EXPLANATION: {value_id}", f"Type: {_type_name(declared.type)}"]
        lines.append("Semantic meaning: not inferred; no source-level symbol is recorded.")
        translator = getattr(self.engine, "debug_address_translator", None)
        binary = self.provenance.module.binary_sha256
        definitions = self.provenance.definitions(value_id)
        if definitions:
            lines.append("CIR DEFINITIONS:")
            for definition in definitions:
                inputs = ", ".join(definition.input_value_ids) or "none"
                lines.append(f"  - Kind: {definition.effect_kind}; Operation: {definition.operation}; Output: {definition.value_id}; Inputs: [{inputs}]")
                lines.append(f"    Block RVA: 0x{definition.block_rva:x}; Effect Index: {definition.effect_index}; Origin: {definition.origin_id}")
                if definition.operand_descriptions:
                    lines.append("    Operand Details: " + "; ".join(definition.operand_descriptions))
                if translator is not None:
                    lines.append("    " + translator.format_address(binary, definition.block_rva, "Definition block"))
                for input_id in definition.input_value_ids:
                    input_value = self.provenance.value(input_id)
                    lines.append(f"    Input {input_id}: " + ("NOT_DECLARED_IN_CIR" if input_value is None else _type_name(input_value.type)))
        else:
            lines.append(
                "CIR definitions: unavailable (declared synthetic/interface value)"
            )
        origins = self.provenance.origins(value_id)
        if not origins:
            lines.append("Origins: NOT_RECORDED (no defining effect or frontend source hint references OriginMap).")
            lines.append("Origin Type: SYNTHETIC_OR_UNMAPPED; reason=NO_ORIGIN_RECORD")
        lines.append("Origins:")
        for item in origins:
            point = item.origin.point
            instruction = (
                f"0x{point.instruction_rva:x}"
                if point.instruction_rva is not None
                else "none (synthetic)"
            )
            statement = (
                str(point.statement)
                if point.statement is not None
                else "none"
            )
            lines.append(
                f"  - function RVA=0x{point.function.rva:x}; block RVA=0x{point.block.rva:x}; "
                f"statement index={statement}; instruction RVA={instruction}; "
                f"VEX opcode={item.origin.source_opcode}; role={item.role}"
            )
            if translator is not None:
                lines.append("    " + translator.format_address(binary, point.function.rva, "Function"))
                lines.append("    " + translator.format_address(binary, point.block.rva, "Basic block"))
                lines.append("    " + translator.format_address(binary, point.instruction_rva, "Instruction"))
            else:
                lines.append("    IDA VA: unavailable (configure --debug-ida-image-base)")
            instruction_hint = item.instruction or self.provenance.instruction_record(item.origin.id)
            if instruction_hint is None:
                lines.append("    Instruction detail: NOT_RECORDED (legacy acquisition or missing IMark).")
            else:
                lines.append("    VEX statement: " + (instruction_hint.vex_statement_text or "NOT_RECORDED"))
                lines.append("    Machine bytes: " + (instruction_hint.instruction_bytes_hex or "NOT_RECORDED"))
                lines.append("    Assembly: " + (instruction_hint.assembly_text or "NOT_DECODED"))
                if instruction_hint.mode is not None:
                    lines.append("    Decode mode: " + instruction_hint.mode)
            if item.vex_statement_kind is not None:
                lines.append(f"    VEX statement: {item.vex_statement_kind}")
            if item.vex_temporary is not None:
                lines.append(f"    VEX temporary: t{item.vex_temporary}")
            if item.register_name is not None or item.register_offset is not None:
                register = item.register_name or "unknown-name"
                offset = (
                    str(item.register_offset)
                    if item.register_offset is not None
                    else "unknown-offset"
                )
                lines.append(f"    Register: {register} (VEX offset {offset})")
                lines.append(f"    Register access: {item.role}; width={declared.type.bits} bits (CIR value type).")
                lines.append("    Register width/access: NOT_RECORDED_IN_SOURCE_HINT (not inferred).")
        if not origins:
            lines.append("Origin Type: SYNTHETIC_OR_UNMAPPED")
            lines.append("Reason: no defining CIR effect or frontend source hint references this ValueRef.")
        if max_depth < 0 or max_nodes < 1:
            raise ValueError("Dependency limits require depth >= 0 and nodes >= 1")
        if not summary and definitions:
            lines.append("CIR INPUT DEPENDENCIES:")
            pending = [(item, 1) for definition in definitions for item in definition.input_value_ids]
            visited, emitted = {value_id}, 0
            while pending:
                input_id, depth = pending.pop(0)
                if input_id in visited:
                    lines.append("  " * depth + input_id + " (shared/cycle)")
                    continue
                if emitted >= max_nodes:
                    lines.append(f"... dependency node limit {max_nodes} reached")
                    break
                visited.add(input_id); emitted += 1
                input_value = self.provenance.value(input_id)
                if input_value is None:
                    lines.append("  " * depth + f"{input_id}: NOT_DECLARED_IN_CIR")
                    continue
                lines.append("  " * depth + f"{input_id}: {_type_name(input_value.type)}")
                if depth < max_depth:
                    pending.extend((nested, depth + 1) for definition in self.provenance.definitions(input_id) for nested in definition.input_value_ids)
                elif self.provenance.definitions(input_id):
                    lines.append("  " * (depth + 1) + f"... depth limit {max_depth} reached")
        return "\n".join(lines)

    def _node_line(self, expression: SymbolicExprId, node: object) -> str:
        """Render the semantic payload of one already-existing SSE node."""

        detail = ""
        if node.op == SymbolicOp.CONSTANT:
            detail = f" value={node.value!r}"
        elif node.op in (SymbolicOp.SYMBOL, SymbolicOp.UNKNOWN):
            detail = f" meaning={node.value!r}"
        elif node.params:
            detail = f" params={node.params}"
        return (
            f"{expression.key}: {node.op.value}{detail} "
            f"[{_type_name(node.type)}] origin={node.origin}"
        )

    def _memory_lines(self, node: object, indent: str) -> list[str]:
        """Describe recorded memory objects directly, without resolving them."""

        if node.op != SymbolicOp.MEMORY_READ:
            return []
        lines = [
            f"{indent}Memory version: {node.state.key}",
            f"{indent}Location: {node.location.key}",
        ]
        locations = getattr(self.engine, "locations", {})
        location = locations.get(node.location)
        if location is None:
            lines.append(f"{indent}Memory detail: unavailable in attached engine")
            return lines
        object_id = location.object_id
        lines.append(
            f"{indent}Range: {location.offset_lower}..{location.offset_upper} "
            f"width={location.width_bits} endian={location.endian.value}"
        )
        lines.append(
            f"{indent}Object: {object_id.kind.value if object_id else 'unknown'}"
        )
        return lines

    def explain_expr(
        self,
        expression: SymbolicExprId,
        *,
        max_depth: int = 5,
        max_nodes: int = 100,
        show_origins: bool = True,
        show_memory: bool = True,
    ) -> str:
        """Render a bounded SSE DAG with shared-node references."""

        if max_depth < 0 or max_nodes < 1:
            raise ValueError("Expression limits require depth >= 0 and nodes >= 1")
        dag = getattr(self.engine, "dag", None)
        if dag is None:
            return (
                f"Expression {expression.key}\n"
                "Unavailable: no SSE DAG is attached."
            )
        if expression not in dag.nodes:
            return (
                f"Expression {expression.key}\n"
                "Unavailable: expression is not present in the attached DAG."
            )

        root_node = dag.nodes[expression]
        lines: list[str] = [f"SEMANTIC VIEW: {expression.key}", f"Operation: {root_node.op.value}",
                            f"Type: {_type_name(root_node.type)}", f"Operand count: {len(root_node.operands)}"]
        translator = getattr(self.engine, "debug_address_translator", None)
        if root_node.origin:
            origin = self.provenance.origin_record(root_node.origin) if self.provenance else self.engine.origin_record(root_node.origin)
            if origin is not None:
                point = origin.point
                lines.append(f"Origin opcode: {origin.source_opcode}")
                if translator is not None:
                    lines.append("  " + translator.format_address(self.provenance.module.binary_sha256, point.instruction_rva, "Origin instruction"))
                else:
                    lines.append(f"  Instruction RVA: {point.instruction_rva!r}; IDA VA unavailable")
        if root_node.op == SymbolicOp.COPY:
            chain, current, visited_copy = [], expression, set()
            while current in dag.nodes and current not in visited_copy:
                visited_copy.add(current); item = dag.nodes[current]
                if item.op != SymbolicOp.COPY or len(item.operands) != 1: break
                chain.append(current); current = item.operands[0]
            if len(chain) > 1:
                lines.append(f"Copy Chain: {len(chain)} COPY nodes (original DAG retained)")
                lines.append(f"Original source: {current.key}")
                source = dag.nodes.get(current)
                if source is not None and source.op == SymbolicOp.UNKNOWN:
                    lines.append(f"Original source status: UNKNOWN; reason={source.value}")
        lines.append("DAG VIEW:")
        seen: set[SymbolicExprId] = set()
        pending = [(expression, 0)]
        while pending:
            reference, depth = pending.pop()
            indent = "  " * depth
            if reference in seen:
                lines.append(f"{indent}↳ {reference.key} (shared)")
                continue
            if len(seen) >= max_nodes:
                lines.append(f"{indent}… node limit {max_nodes} reached")
                break
            node = dag.nodes.get(reference)
            if node is None:
                lines.append(f"{indent}{reference.key}: missing DAG node")
                continue
            seen.add(reference)
            line = self._node_line(reference, node)
            if not show_origins:
                line = line.rsplit(" origin=", 1)[0]
            lines.append(indent + line)
            recorder = getattr(self.demand, "_trace_recorder", None)
            if recorder is not None:
                for event in recorder.events_for(reference):
                    lines.append(f"{indent}  Creation/propagation event: #{event.sequence} {event.event_id} {event.rule}")
                    if event.reason:
                        lines.append(f"{indent}    Reason: {event.reason}")
                    for key, value in event.details:
                        lines.append(f"{indent}    {key}: {value}")
            if show_memory:
                lines.extend(self._memory_lines(node, indent + "  "))
                loads = getattr(self.demand, "loads", {})
                if reference in loads:
                    address, width, endian, _ = loads[reference]
                    lines.append(
                        f"{indent}  Address expression: {address.key} "
                        f"width={width} endian={endian.value}"
                    )
            if node.operands:
                if depth >= max_depth:
                    lines.append(f"{indent}  … depth limit {max_depth} reached")
                else:
                    pending.extend(
                        (operand, depth + 1)
                        for operand in reversed(node.operands)
                    )
        return "\n".join(lines)

    def explain_demand_value(self, demand: object, value: ValueRef) -> str:
        """Explain cached roots without executing a new demand or memory query."""

        cache_key = ("value", value.id)
        roots = demand.memo.get(cache_key)
        recorder = getattr(demand, "_trace_recorder", None)
        value_events = recorder.events_for(value.id) if recorder is not None else ()
        if roots is None and self.engine is not None:
            traced_keys = tuple(
                output
                for event in value_events
                if event.rule.startswith("DEMAND_")
                for output in event.output_ids
            )
            roots = tuple(
                reference
                for reference in self.engine.dag.nodes
                if reference.key in traced_keys
            ) or None
        lines = [f"Demand value {value.id}"]
        if roots is None:
            lines.append(
                "Roots unavailable: the value has no completed cached demand result; "
                "the inspector will not execute demand.value()."
            )
            return "\n".join(lines)
        lines.append(f"Roots: {len(roots)}")
        for root in roots:
            node = self.engine.dag.nodes.get(root) if self.engine else None
            semantic = node.op.value if node is not None else "missing"
            lines.append(f"  - {root.key}: operation={semantic}")
            if node is not None:
                origin = (
                    self.provenance.origin_record(node.origin)
                    if self.provenance is not None
                    else None
                )
                if origin is not None:
                    instruction = origin.point.instruction_rva
                    rendered = (
                        f"0x{instruction:x}" if instruction is not None else "synthetic"
                    )
                    lines.append(
                        f"    Created at: instruction RVA {rendered} ({origin.source_opcode})"
                    )
                    translator = getattr(self.engine, "debug_address_translator", None)
                    if translator is not None and instruction is not None:
                        lines.append("      " + translator.format_address(
                            self.provenance.module.binary_sha256, instruction, "Instruction"
                        ))
                    elif instruction is not None:
                        lines.append("      IDA VA unavailable (IDA_IMAGE_BASE_NOT_CONFIGURED)")
                else:
                    lines.append(
                        f"    Created at: unresolved origin {node.origin}"
                    )
            derivations = [
                event
                for event in value_events
                if root.key in event.output_ids
            ]
            for event in derivations:
                reason = f" reason={event.reason}" if event.reason else ""
                lines.append(
                    f"    Rule #{event.sequence} [{event.event_id}]: {event.rule}{reason}"
                )
                description = self._rule_description(event.rule)
                if description:
                    lines.append("      Action: " + description)
            if recorder is not None:
                causal = recorder.causal_slice(root)
                lines.append(f"    Causal events: {len(causal)}")
                for event in causal:
                    details = "; ".join(f"{key}={value}" for key, value in event.details)
                    lines.append(
                        f"      #{event.sequence} {event.rule}: "
                        f"inputs={list(event.input_ids)} outputs={list(event.output_ids)} "
                        f"origin={event.origin_id} {details}"
                    )
        if len(roots) > 1:
            groups = {}
            for root in roots:
                groups.setdefault(self._expression_fingerprint(root, max_nodes=512), []).append(root)
            lines.append("ROOT DIFFERENCE SUMMARY:")
            for fingerprint, members in groups.items():
                lines.append(f"  Group {fingerprint}: {len(members)} root(s) " + ", ".join(item.key for item in members))
            lines.append(f"  Distinct bounded structural fingerprints: {len(groups)}")
            lines.append("  Fingerprints describe DAG shape only; they do not establish path feasibility or semantic equivalence.")
        if recorder is None:
            lines.append("Root explanation: INCOMPLETE")
            lines.append("Missing evidence: ROOT_CREATION_CAUSALITY_NOT_RECORDED")
        rules = tuple(sorted(getattr(demand, "rules", ())))
        lines.append(
            "Observed rules: " + (", ".join(rules) if rules else "none recorded")
        )
        return "\n".join(lines)


    @staticmethod
    def _rule_description(rule: str) -> str | None:
        """Describe only explicitly registered analysis rules."""
        descriptions = {
            "DEMAND_CONSTANT": "Materialize a typed CIR constant as an SSE constant leaf.",
            "DEMAND_VALUE_CACHE_HIT": "Reuse the completed memoized demand result for this CIR ValueRef.",
            "DEMAND_VALUE_UNDEFINED": "Create an explicit Unknown because the CIR value has no local definition in this demand scope.",
            "DEMAND_COMPUTE": "Expand the operands of a CIR Compute and apply its recorded ValueOp.",
            "DEMAND_REGISTER_DEFINITION": "Resolve the register read through the backward register definition chain.",
            "DEMAND_MEMORY_LOAD": "Resolve the LoadEffect address and enumerate its recorded reaching memory definitions.",
            "DEMAND_CALL_RETURN": "Instantiate the available callee return summary or preserve an unresolved-return Unknown.",
            "MEMORY_REACHING_STORE_ALIAS": "Compare one encountered Store location with the requested Load location using the actual alias result.",
            "MEMORY_REACHING_STORE_UNKNOWN": "Preserve a may-flow Unknown for a non-MUST reaching Store; this is not a confirmed alias.",
            "MEMORY_READ_QUERY": "Create a versioned memory-read expression at the supplied memory state and location.",
            "SSE_UNKNOWN_CREATE": "Create an explicit Unknown SSE leaf with the recorded precision-loss reason.",
            "MEMORY_ALIAS_QUERY": "Record the result of the actual MemoryQueryPort alias decision.",
        }
        return descriptions.get(rule)

    def _expression_fingerprint(self, expression: SymbolicExprId, *, max_nodes: int = 512) -> str:
        """Return a bounded structural fingerprint without simplifying the DAG."""
        dag = getattr(self.engine, "dag", None)
        if dag is None or expression not in dag.nodes:
            return "NOT_AVAILABLE"
        pending, values, visits = [(expression, False)], {}, 0
        while pending:
            current, ready = pending.pop()
            if current in values: continue
            node = dag.nodes.get(current)
            if node is None:
                values[current] = "MISSING"; continue
            if not ready:
                visits += 1
                if visits > max_nodes:
                    values[current] = "NODE_LIMIT"; continue
                pending.append((current, True))
                pending.extend((operand, False) for operand in reversed(node.operands) if operand not in values)
            else:
                values[current] = (node.op.value, _type_name(node.type), repr(node.value),
                    tuple(values.get(operand, "UNRESOLVED") for operand in node.operands))
        import hashlib
        return hashlib.sha256(repr(values.get(expression)).encode("utf8")).hexdigest()[:16]

    def explain_memory_version(self, version: object, *, max_depth: int = 32) -> str:
        """Explain existing memory-version ancestry without issuing queries."""
        if max_depth < 0:
            raise ValueError("max_depth must be non-negative")
        versions = getattr(self.engine, "versions", {})
        if version not in versions:
            return f"Memory version {version}: unavailable."
        lines = [f"MEMORY VERSION: {version.key}"]
        pending, seen = [(version, 0)], set()
        while pending and len(seen) < 512:
            current, depth = pending.pop()
            if current in seen:
                continue
            seen.add(current)
            record = versions.get(current)
            if record is None:
                continue
            definition = record.definition
            indent = "  " * (depth + 1)
            lines.append(f"{indent}{type(definition).__name__}: {current.key}")
            origin_id = getattr(definition, "origin", None)
            lines.append(f"{indent}Origin: {origin_id or 'initial/synthetic'}")
            if origin_id is not None and self.provenance is not None:
                origin_record = self.provenance.origin_record(origin_id)
                translator = getattr(self.engine, "debug_address_translator", None)
                if origin_record is not None and translator is not None:
                    lines.append(indent + translator.format_address(
                        self.provenance.module.binary_sha256,
                        origin_record.point.instruction_rva,
                        "Instruction",
                    ))
            if hasattr(definition, "location"):
                location = self.engine.locations.get(definition.location)
                if location is not None:
                    lines.append(f"{indent}Location: object={location.object_id}; range=[{location.offset_lower},{location.offset_upper}]; width={location.width_bits}; endian={location.endian.value}")
                lines.append(f"{indent}Value: {getattr(definition, 'value', None)}")
                lines.append(f"{indent}Guard: {getattr(definition, 'guard', None)}")
                alias = getattr(definition, "alias", None)
                if alias is not None:
                    lines.append(f"{indent}Update: {definition.update.value}; alias={alias.kind.value}")
                    lines.append(f"{indent}Alias evidence: {list(alias.evidence)}")
                    lines.append(f"{indent}Strong-update preconditions: unique={definition.unique_target}; exact-coverage={definition.exact_coverage}")
            if hasattr(definition, "regions"):
                lines.append(f"{indent}Havoc regions: {list(definition.regions)}; reason={definition.reason}")
            if hasattr(definition, "inputs"):
                for item in definition.inputs:
                    lines.append(f"{indent}Join input: version={item.version}; guard={item.guard}")
            parents = tuple(record.parents)
            if depth >= max_depth and parents:
                lines.append(f"{indent}... depth limit {max_depth} reached")
            else:
                pending.extend((parent, depth + 1) for parent in reversed(parents))
        if pending:
            lines.append("... ancestry node limit 512 reached")
        reads = [item for item in getattr(self.engine, "reads", ()) if item.state == version]
        lines.append(f"Reads at this version: {len(reads)}")
        for item in reads[:64]:
            lines.append(f"  Read {item.result.key}: location={item.location.key}; guard={item.guard}; origin={item.origin}")
        return "\n".join(lines)

    def explain_memory_read(self, expression: SymbolicExprId) -> str:
        """List structurally ancestral candidate stores without new alias queries."""
        dag = getattr(self.engine, "dag", None)
        if dag is None or expression not in dag.nodes:
            return f"Memory read {expression.key}: unavailable."
        node = dag.nodes[expression]
        if node.op != SymbolicOp.MEMORY_READ:
            return f"Expression {expression.key} is not a memory read."
        location = self.engine.locations.get(node.location)
        if location is None:
            return "Memory read location descriptor is missing."
        lines = [f"MEMORY READ: {expression.key}", f"State: {node.state.key}",
                 f"Location: {location.id.key}", f"Object/range: {location.object_id}; {location.byte_interval}"]
        translator = getattr(self.engine, "debug_address_translator", None)
        origin_record = self.provenance.origin_record(node.origin) if self.provenance is not None else None
        if origin_record is not None:
            lines.append(f"Load origin: {node.origin}; instruction RVA={origin_record.point.instruction_rva!r}")
            if translator is not None:
                lines.append(translator.format_address(self.provenance.module.binary_sha256,
                    origin_record.point.instruction_rva, "Load instruction"))
        reads = [item for item in self.engine.reads if item.result == expression]
        if reads:
            lines.append("Read guards: " + ", ".join(str(item.guard) for item in reads))
        recorder = getattr(self.demand, "_trace_recorder", None)
        if recorder is not None:
            for event in recorder.events_for(expression):
                lines.append(f"Recorded read event: #{event.sequence} {event.event_id} {event.rule}; reason={event.reason}")
                for key, value in event.details:
                    lines.append(f"  {key}: {value}")
        pending, seen, candidates = [node.state], set(), []
        while pending and len(seen) < 512:
            state = pending.pop()
            if state in seen:
                continue
            seen.add(state)
            record = self.engine.versions.get(state)
            if record is None:
                continue
            definition = record.definition
            if hasattr(definition, "location") and hasattr(definition, "alias"):
                store = self.engine.locations.get(definition.location)
                if store is not None:
                    same_object = location.object_id is not None and location.object_id == store.object_id
                    left, right = location.byte_interval, store.byte_interval
                    overlap = bool(same_object and left and right and max(left[0], right[0]) < min(left[1], right[1]))
                    uncertain = location.object_id is None or store.object_id is None or left is None or right is None or location.object_id != store.object_id
                    if overlap or uncertain:
                        candidates.append((state, definition, store, overlap, uncertain))
            pending.extend(record.parents)
        lines.append("Candidate stores (ancestry only; no alias query executed):")
        if not candidates:
            lines.append("  No candidate store found in the recorded ancestry.")
        for state, definition, store, overlap, uncertain in candidates:
            lines.append(f"  state={state.key}; object={store.object_id}; range={store.byte_interval}; guard={definition.guard}; update={definition.update.value}; recorded-alias={definition.alias.kind.value}; overlap={overlap}; uncertain={uncertain}")
            store_origin = self.provenance.origin_record(definition.origin) if self.provenance is not None else None
            if store_origin is not None:
                lines.append(f"    Store origin RVA: {store_origin.point.instruction_rva!r}")
                if translator is not None:
                    lines.append("    " + translator.format_address(self.provenance.module.binary_sha256,
                        store_origin.point.instruction_rva, "Store instruction"))
            lines.append("  evidence=" + "; ".join(definition.alias.evidence or definition.alias.assessment.precision_loss))
        lines.append("Candidate ancestry is not proof that a store reaches this read; path feasibility and alias precision remain separate obligations.")
        return "\n".join(lines)

    def explain_alias(self, state: object, left: object, right: object, result: object | None = None) -> str:
        """Explain a supplied or cached alias answer without issuing a query."""
        lines = [f"ALIAS QUERY: state={getattr(state, 'key', state)}",
                 f"Left: {left.id.key}; object={left.object_id}; range={left.byte_interval}",
                 f"Right: {right.id.key}; object={right.object_id}; range={right.byte_interval}"]
        translator = getattr(self.engine, "debug_address_translator", None)
        if translator is not None and self.provenance is not None:
            for label, location in (("Left origin", left), ("Right origin", right)):
                origin = self.provenance.origin_record(getattr(location, "origin", ""))
                if origin is not None:
                    lines.append(translator.format_address(self.provenance.module.binary_sha256,
                        origin.point.instruction_rva, label))
        if result is None:
            cache = getattr(getattr(self.demand, "port", None), "_alias_cache", {})
            for key, cached in cache.items():
                unknown_pair = left.object_id is None and right.object_id is None and key == (state, "unknown-object")
                known_pair = key[0] == state and left.object_id is not None and right.object_id is not None and left.object_id in key and right.object_id in key
                if unknown_pair or known_pair:
                    result = cached
                    break
        if result is None:
            lines.append("Result: NOT_CACHED; inspector will not execute resolve_alias().")
        else:
            lines.append(f"Result: {result.kind.value}; evidence={list(result.evidence)}")
            lines.append(f"Completeness: {result.assessment.status.value}; precision={result.assessment.precision.value}")
        return "\n".join(lines)

    def explain_instruction(self, origin_id: str) -> str:
        """Render captured VEX, bytes, assembly and address for one origin."""
        if self.provenance is None:
            return "Instruction provenance unavailable."
        hint = self.provenance.instruction_record(origin_id)
        origin = self.provenance.origin_record(origin_id)
        if hint is None or origin is None:
            return f"Instruction {origin_id}: NOT_RECORDED."
        translator = getattr(self.engine, "debug_address_translator", None)
        lines = [f"ORIGIN: {origin_id}",
                 "VEX statement: " + (hint.vex_statement_text or "NOT_RECORDED"),
                 "Machine bytes: " + (hint.instruction_bytes_hex or "NOT_RECORDED"),
                 "Assembly: " + (hint.assembly_text or "NOT_DECODED"),
                 "Mode: " + (hint.mode or "unknown")]
        if translator is not None:
            lines.append(translator.format_address(self.provenance.module.binary_sha256, hint.instruction_rva, "Instruction"))
        else:
            lines.append(f"Instruction RVA: {hint.instruction_rva!r}; IDA VA unavailable")
        return "\n".join(lines)

    def explain_taint_state(self, *, max_items: int = 64) -> str:
        """Explain recorded source, sink, guard and query evidence without re-analysis."""
        if max_items < 1:
            raise ValueError("max_items must be positive")
        owner = getattr(self.demand, "taint_owner", None)
        if owner is None:
            return "Taint evidence unavailable: no LegacyTaintDemand is attached."
        lines = ["TAINT ANALYSIS EVIDENCE", f"Function RVA: 0x{owner.function.function_id.rva:x}",
                 f"Completed sinks: {len(owner.completed_sinks)}"]
        translator = getattr(self.engine, "debug_address_translator", None)
        binary = self.provenance.module.binary_sha256 if self.provenance is not None else None
        if translator is not None and binary is not None:
            lines.append(translator.format_address(binary, owner.function.function_id.rva, "Function"))
        for sink in owner.completed_sinks[:max_items]:
            lines.append("  Sink: " + repr(sink))
            if translator is not None and binary is not None:
                sink_site = getattr(sink, "site", None)
                if type(sink_site) is int:
                    sink_rva = sink_site - getattr(owner, "base", 0)
                    if sink_rva >= 0:
                        lines.append("    " + translator.format_address(binary, sink_rva, "Sink instruction"))
        lines.append(f"Source bindings: {len(owner.source_bindings)}")
        for key, binding in list(owner.source_bindings.items())[:max_items]:
            lines.append(f"  Source binding {key}: {binding!r}")
        lines.append(f"Imported source bindings: {len(owner.imported_bindings)}")
        for key, binding in list(owner.imported_bindings.items())[:max_items]:
            lines.append(f"  Imported source {key}: {binding!r}")
        lines.append(f"Unknown evidence items: {len(owner.unknown_evidence)}")
        for item in sorted(owner.unknown_evidence)[:max_items]:
            lines.append("  Unknown: " + str(item))
        lines.append(f"Pending queries: {len(owner.query_pending)}")
        for key, value in list(owner.query_pending.items())[:max_items]:
            lines.append(f"  Pending query {key}: {value!r}")
        lines.append(f"Query history items: {len(owner.query_history)}")
        for item in owner.query_history[-max_items:]:
            lines.append("  Query: " + repr(item))
        lines.append(f"Path-guard cache entries: {len(owner.path_guard_cache)}")
        for key, value in list(owner.path_guard_cache.items())[:max_items]:
            lines.append(f"  Call origin {key}: guards={value!r}")
        lines.append("These are recorded may-evidence and analysis states, not proof of path feasibility or a confirmed vulnerability.")
        return "\n".join(lines)

    def inspect_memory_version(self, version: object, **limits: object) -> str:
        """VS Code Watch entry point for a memory-version history report."""
        return self.explain_memory_version(version, **limits)

    def inspect_memory_read(self, expression: SymbolicExprId) -> str:
        """VS Code Watch entry point for reaching-store candidates."""
        return self.explain_memory_read(expression)

    def inspect_alias(self, state: object, left: object, right: object, result: object | None = None) -> str:
        """VS Code Watch entry point for a cached alias decision."""
        return self.explain_alias(state, left, right, result)

    def inspect_instruction(self, origin_id: str) -> str:
        """VS Code Watch entry point for VEX/bytes/assembly provenance."""
        return self.explain_instruction(origin_id)

    def inspect_trace(self, identity: object, *, max_events: int = 512) -> str:
        """Render the bounded backward causal slice for one existing identity."""
        recorder = getattr(self.demand, "_trace_recorder", None)
        if recorder is None:
            return "Trace unavailable: --debug-trace was not enabled during analysis."
        events = recorder.causal_slice(identity, max_events=max_events)
        lines = [f"CAUSAL TRACE: {identity}", f"Events: {len(events)}", f"Dropped: {recorder.dropped}"]
        for event in events:
            lines.append(
                f"#{event.sequence} {event.event_id} {event.rule}: "
                f"{list(event.input_ids)} -> {list(event.output_ids)}; origin={event.origin_id}; reason={event.reason}"
            )
        return "\n".join(lines)

    def inspect_value(self, value: ValueRef | str, **limits: object):
        """Return a value report directly for a VS Code Watch expression."""
        return self.explain_value(value, **limits)

    def inspect_expr(self, expression: SymbolicExprId, **limits: object) -> str:
        """Return a bounded expression report directly for VS Code Watch."""
        return self.explain_expr(expression, **limits)

    def inspect_demand_value(self, demand: object, value: ValueRef) -> str:
        """Return the cached demand report directly for VS Code Watch."""
        return self.explain_demand_value(demand, value)

    def inspect_ida_va(self, ida_va: int) -> str:
        """Reverse an IDA EA to all recorded instructions, CIR values and SSE nodes."""
        if self.provenance is None:
            return "IDA lookup unavailable: no provenance index is attached."
        translator = getattr(self.engine, "debug_address_translator", None)
        if translator is None:
            return "IDA lookup unavailable: configure --debug-ida-image-base."
        binary = self.provenance.module.binary_sha256
        rva = translator.to_rva(binary, ida_va)
        if rva is None:
            return f"IDA VA 0x{ida_va:x}: NOT_MAPPED (no base or address precedes the configured image base)."
        records = self.provenance.instructions_for_rva(binary, rva)
        values = self.provenance.values_for_instruction(binary, rva)
        lines = [f"IDA VA 0x{ida_va:x} (RVA 0x{rva:x})", f"Instruction records: {len(records)}"]
        for record in records:
            lines.append(f"  Origin: {record.origin_id}; statement={record.statement_index}; opcode={record.source_opcode}")
            lines.append("  VEX: " + (record.vex_statement_text or "NOT_RECORDED"))
            lines.append("  Assembly: " + (record.assembly_text or "NOT_DECODED"))
        lines.append(f"CIR ValueRefs: {len(values)}")
        for value in values:
            lines.append(f"  {value.id}: {_type_name(value.type)}")
        dag = getattr(self.engine, "dag", None)
        matches = []
        if dag is not None:
            origin_ids = {item.origin_id for item in records}
            matches = [reference for reference, node in dag.nodes.items() if node.origin in origin_ids]
        lines.append(f"SSE expressions sharing these instruction origins: {len(matches)}")
        for reference in matches:
            lines.append(f"  {reference.key}: {dag.nodes[reference].op.value}")
        return "\n".join(lines)


    def export_report(
        self,
        directory: str | Path,
        *,
        max_values: int = 256,
        max_expressions: int = 512,
        max_depth: int = 8,
        max_nodes: int = 256,
    ) -> Path:
        """Export a bounded, read-only explainability bundle for this session.

        The method only traverses existing CIR/provenance/DAG/memory/trace
        objects. It never invokes Demand.value(), alias, memory or solver APIs.
        """
        if max_values < 1 or max_expressions < 1 or max_depth < 0 or max_nodes < 1:
            raise ValueError("Debug report limits must be positive (depth may be zero)")
        destination = Path(directory)
        destination.mkdir(parents=True, exist_ok=False)
        for name in ("values", "expressions", "memory", "reports"):
            (destination / name).mkdir()
        binary = None if self.provenance is None else self.provenance.module.binary_sha256
        translator = getattr(self.engine, "debug_address_translator", None)
        session = {
            "schema_version": "BinaryAnalysis-Debug-Report-v1",
            "binary_sha256": binary,
            "ida_image_base": None if translator is None else translator.ida_image_base,
            "runtime_base": None if translator is None else translator.runtime_base,
            "provenance_source_hints": bool(self.provenance and self.provenance.source_hints_available),
            "provenance_instruction_hints": bool(self.provenance and self.provenance.instruction_hints_available),
            "analysis_trace_enabled": getattr(self.demand, "_trace_recorder", None) is not None,
            "analysis_trace_missing_reason": None if getattr(self.demand, "_trace_recorder", None) is not None else "TRACE_NOT_ENABLED_DURING_ANALYSIS",
            "read_only": True,
            "limits": {"max_values": max_values, "max_expressions": max_expressions,
                       "max_depth": max_depth, "max_nodes": max_nodes},
        }
        (destination / "session.json").write_text(
            json.dumps(session, indent=2, sort_keys=True, default=str) + "\\n", encoding="utf8"
        )
        (destination / "README.md").write_text(
            "# BinaryAnalysis Debug Report\\n\\n"
            "- `session.json`: binary identity, address configuration and completeness flags\\n"
            "- `provenance.json`: OriginMap and captured VEX/instruction records\\n"
            "- `analysis-events.jsonl`: recorded causal rule events (empty if tracing was disabled)\\n"
            "- `values/`: bounded CIR value explanations\\n"
            "- `expressions/`: bounded SSE expression explanations\\n"
            "- `memory/`: recorded memory-version ancestry\\n"
            "- `reports/`: demand, taint and address mapping summaries\\n",
            encoding="utf8",
        )
        if self.provenance is not None:
            provenance_rows = []
            for origin in self.provenance.module.origin_map:
                point = origin.point
                row = {
                    "origin_id": origin.id,
                    "source_opcode": origin.source_opcode,
                    "function_rva": hex(point.function.rva),
                    "block_rva": hex(point.block.rva),
                    "statement_index": point.statement,
                    "instruction_rva": None if point.instruction_rva is None else hex(point.instruction_rva),
                    "instruction_address": None if translator is None else translator.address_fields(binary, point.instruction_rva),
                    "instruction_hint": None if self.provenance.instruction_record(origin.id) is None else asdict(self.provenance.instruction_record(origin.id)),
                    "value_ids": [value.id for value in self.provenance.values_for_origin(origin.id)],
                }
                provenance_rows.append(row)
            (destination / "provenance.json").write_text(
                json.dumps(provenance_rows, indent=2, sort_keys=True, default=str) + "\\n", encoding="utf8"
            )
            values = tuple(self.provenance._values.values())[:max_values]
            for value in values:
                report = self.explain_value(value, max_depth=max_depth, max_nodes=max_nodes)
                (destination / "values" / (value.id.replace(":", "_") + ".md")).write_text(report + "\\n", encoding="utf8")
            (destination / "values" / "index.json").write_text(
                json.dumps({"total_values": len(self.provenance._values), "exported_values": len(values),
                            "truncated": len(self.provenance._values) > len(values)},
                           indent=2, sort_keys=True) + "\\n", encoding="utf8"
            )
        dag = getattr(self.engine, "dag", None)
        if dag is not None:
            expressions = tuple(dag.nodes)[:max_expressions]
            for expression in expressions:
                report = self.explain_expr(expression, max_depth=max_depth, max_nodes=max_nodes)
                (destination / "expressions" / (expression.key.replace(":", "_") + ".md")).write_text(report + "\\n", encoding="utf8")
            (destination / "expressions" / "index.json").write_text(
                json.dumps({"total_expressions": len(dag.nodes), "exported_expressions": len(expressions),
                            "truncated": len(dag.nodes) > len(expressions)},
                           indent=2, sort_keys=True) + "\\n", encoding="utf8"
            )
            versions = getattr(self.engine, "versions", {})
            memory_index = []
            for version in tuple(versions)[:max_expressions]:
                report = self.explain_memory_version(version, max_depth=max_depth)
                (destination / "memory" / (version.key.replace(":", "_") + ".md")).write_text(report + "\\n", encoding="utf8")
                memory_index.append({"version": version.key, "definition": type(versions[version].definition).__name__})
            (destination / "memory" / "index.json").write_text(
                json.dumps({"total_versions": len(versions), "exported_versions": len(memory_index),
                            "versions": memory_index}, indent=2, sort_keys=True, default=str) + "\\n",
                encoding="utf8"
            )
        recorder = getattr(self.demand, "_trace_recorder", None)
        if recorder is not None:
            recorder.export_jsonl(
                destination / "analysis-events.jsonl",
                address_translator=translator,
                binary_id=binary,
            )
        else:
            (destination / "analysis-events.jsonl").write_text("", encoding="utf8")
        demand_owner = self.demand
        taint_owner = getattr(demand_owner, "taint_owner", None)
        if demand_owner is not None:
            memo_values = [
                key[1] for key in getattr(demand_owner, "memo", {})
                if isinstance(key, tuple) and len(key) == 2 and key[0] == "value"
            ]
            demand_reports = []
            for value_id in dict.fromkeys(memo_values):
                value = self.provenance.value(value_id) if self.provenance is not None else None
                if value is None:
                    continue
                demand_reports.append(self.explain_demand_value(demand_owner, value))
            (destination / "reports" / "demand-explanations.md").write_text(
                "\\n\\n---\\n\\n".join(demand_reports) + ("\\n" if demand_reports else "No completed demand roots were cached.\\n"),
                encoding="utf8"
            )
        if taint_owner is not None:
            (destination / "reports" / "taint-evidence.md").write_text(
                self.explain_taint_state() + "\\n", encoding="utf8"
            )
        (destination / "reports" / "address-mapping.md").write_text(
            "Address mapping\\n\\n" +
            ("IDA image base was not configured. No IDA VA values are fabricated.\\n"
             if translator is None or translator.ida_image_base is None else
             f"IDA image base: 0x{translator.ida_image_base:x}\\n") +
            ("Runtime base: unavailable\\n" if translator is None or translator.runtime_base is None
             else f"Runtime base: 0x{translator.runtime_base:x}\\n"),
            encoding="utf8"
        )
        return destination

    def inspect_report(self, directory: str | Path, **limits: object) -> str:
        """VS Code Watch helper: export a bounded report and return its path."""
        return str(self.export_report(directory, **limits))

    def ida_index(self, image_base: int):
        """Create an explicit IDA address view over the attached provenance."""

        if self.provenance is None:
            raise ValueError("IDA mapping requires an attached provenance index")
        from .ida_export import IdaAddressIndex

        return IdaAddressIndex(self.provenance, image_base)
