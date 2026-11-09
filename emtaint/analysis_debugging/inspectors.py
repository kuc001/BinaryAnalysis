"""Bounded read-only inspectors for CIR values, SSE DAGs, and demand results."""

from __future__ import annotations

from typing import Any

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

    def explain_value(self, value: ValueRef | str) -> str:
        """Explain CIR definitions and source locations for one value."""

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
            lines.append("CIR definitions:")
            for definition in definitions:
                inputs = ", ".join(definition.input_value_ids) or "none"
                lines.append(
                    f"  - {definition.effect_kind}: {definition.operation}; block RVA=0x{definition.block_rva:x}; "
                    f"effect={definition.effect_index}; origin={definition.origin_id}; inputs=[{inputs}]"
                )
                if definition.operand_descriptions:
                    lines.append("    Operands: " + "; ".join(definition.operand_descriptions))
        else:
            lines.append(
                "CIR definitions: unavailable (declared synthetic/interface value)"
            )
        origins = self.provenance.origins(value_id)
        if not origins:
            lines.append(
                "Origins: unavailable (no defining effect references OriginMap)"
            )
            return "\n".join(lines)
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

        lines: list[str] = []
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
                        f"    Created at: {rendered} ({origin.source_opcode})"
                    )
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
        rules = tuple(sorted(getattr(demand, "rules", ())))
        lines.append(
            "Observed rules: " + (", ".join(rules) if rules else "none recorded")
        )
        return "\n".join(lines)


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
            lines.append(f"{indent}Origin: {getattr(definition, 'origin', 'initial')}")
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
        reads = [item for item in self.engine.reads if item.result == expression]
        if reads:
            lines.append("Read guards: " + ", ".join(str(item.guard) for item in reads))
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
            lines.append("  evidence=" + "; ".join(definition.alias.evidence or definition.alias.assessment.precision_loss))
        lines.append("Candidate ancestry is not proof that a store reaches this read; path feasibility and alias precision remain separate obligations.")
        return "\n".join(lines)

    def explain_alias(self, state: object, left: object, right: object, result: object | None = None) -> str:
        """Explain a supplied or cached alias answer without issuing a query."""
        lines = [f"ALIAS QUERY: state={getattr(state, 'key', state)}",
                 f"Left: {left.id.key}; object={left.object_id}; range={left.byte_interval}",
                 f"Right: {right.id.key}; object={right.object_id}; range={right.byte_interval}"]
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
        for sink in owner.completed_sinks[:max_items]:
            lines.append("  Sink: " + repr(sink))
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

    def inspect_value(self, value: ValueRef | str):
        """Return a value report directly for a VS Code Watch expression."""
        return self.explain_value(value)

    def inspect_expr(self, expression: SymbolicExprId, **limits: object) -> str:
        """Return a bounded expression report directly for VS Code Watch."""
        return self.explain_expr(expression, **limits)

    def inspect_demand_value(self, demand: object, value: ValueRef) -> str:
        """Return the cached demand report directly for VS Code Watch."""
        return self.explain_demand_value(demand, value)

    def ida_index(self, image_base: int):
        """Create an explicit IDA address view over the attached provenance."""

        if self.provenance is None:
            raise ValueError("IDA mapping requires an attached provenance index")
        from .ida_export import IdaAddressIndex

        return IdaAddressIndex(self.provenance, image_base)
