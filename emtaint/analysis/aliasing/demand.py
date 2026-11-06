"""Native pointer demand using shared CIR and memory primitives."""

from emtaint.analysis.taint.demand import ProcedureDemand
from emtaint.core import BlockId
from emtaint.core.contracts import Constant
from emtaint.ir.canonical import (
    CallEffect, Compute, DirectTarget, JumpEffect, UnknownEffect,
)
from emtaint.memory import SymbolicOp
from emtaint.memory.abstract_heap import ObjectCardinality


class AliasProcedureDemand(ProcedureDemand):
    """Provide native-binary address proofs through the shared demand engine.

    Frozen LegacyDemand recognizes the ARM spelling ``sp``. Native binaries
    can use another ABI stack register, so this demand adapter falls back to
    the proof-carrying normalizer already owned by ProcedureDemand.  Unknown
    offsets remain unknown and all alias decisions still go through the
    MemoryQueryPort.
    """

    def __init__(self, function, port, cfg, initial, **kwargs):
        self.alias_cfg = cfg
        super().__init__(function, port, cfg, initial, **kwargs)

    def allocation_cardinality(self, call: CallEffect) -> ObjectCardinality:
        """Prove one allocation per analyzed invocation outside CFG cycles."""

        block = call.site.point.block
        if block not in self.alias_cfg.nodes:
            return ObjectCardinality.SUMMARY
        if any(
                (
                    isinstance(effect, JumpEffect)
                    and not isinstance(effect.target, BlockId)
                ) or (
                    isinstance(effect, UnknownEffect)
                    and effect.may_change_control
                )
                for source in self.function.blocks
                for effect in source.effects):
            return ObjectCardinality.SUMMARY
        successors = {node: set() for node in self.alias_cfg.nodes}
        for edge in self.alias_cfg.edges:
            successors[edge.source].add(edge.target)
        pending = list(successors[block])
        visited = set()
        while pending:
            current = pending.pop()
            if current == block:
                return ObjectCardinality.SUMMARY
            if current in visited:
                continue
            visited.add(current)
            pending.extend(successors.get(current, ()))
        return ObjectCardinality.SINGLETON

    def value(self, operand, depth=0):
        definition = self.defs.get(operand.id) if hasattr(operand, "id") else None
        if definition and isinstance(definition[2], CallEffect):
            call = definition[2]
            summary = (
                self.summaries.get(call.target.function)
                if isinstance(call.target, DirectTarget) else None
            )
            if summary is not None and summary.returns:
                return summary.instantiate(self, call, depth + 1)
        return super().value(operand, depth)

    def _constant_image_address(self, operand, seen=frozenset()):
        """Fold a pure CIR address before selecting its image segment."""

        if isinstance(operand, Constant):
            return operand.value if type(operand.value) is int else None
        if operand.id in seen or operand.id not in self.defs:
            return None
        effect = self.defs[operand.id][2]
        if not isinstance(effect, Compute):
            return None
        next_seen = seen | {operand.id}
        if effect.op.value == "copy":
            return self._constant_image_address(effect.args[0], next_seen)
        if effect.op.value not in ("add", "sub"):
            return None
        left = self._constant_image_address(effect.args[0], next_seen)
        right = self._constant_image_address(effect.args[1], next_seen)
        if type(left) is not int or type(right) is not int:
            return None
        value = left + right if effect.op.value == "add" else left - right
        return value % (1 << self.port.engine.architecture.pointer_bits)

    def local_address(self, operand, seen=frozenset()):
        absolute = self._constant_image_address(operand, seen)
        if type(absolute) is int:
            image = self.port.engine.address(absolute)
            if image is not None:
                return image
        binding = super().local_address(operand, seen)
        if binding is not None and not (
                binding[0].region == "stack" and binding[1] is None):
            return binding
        exact = self.exact_stack_address(operand, seen)
        if exact is not None and exact[1] is not None:
            return exact
        if not hasattr(operand, "id"):
            return binding
        active = getattr(self, "_local_address_demands", set())
        if operand.id in active:
            return binding
        self._local_address_demands = active
        active.add(operand.id)
        try:
            alternatives = self.value(operand)
            resolved = tuple(
                self.address_binding(reference) for reference in alternatives
            )
        finally:
            active.remove(operand.id)
        if resolved and all(
                candidate is not None and candidate == resolved[0]
                for candidate in resolved):
            return resolved[0]
        return binding

    def address_binding(self, reference, seen=frozenset()):
        allocation = getattr(self, "allocation_bindings", {}).get(reference)
        if allocation is not None:
            return allocation
        binding = super().address_binding(reference, seen)
        if binding is not None:
            return binding
        proof = self.address_normalizer.indexed_stack_address(reference)
        # The affine residue describes a family of offsets.  Binding it to
        # proof.offset as an exact location turns an indexed read into a
        # false singleton and can produce a complete false NOALIAS.
        return None if proof is None else (proof.root, None)

    def uninitialized_frame_pointer(self, reference, seen=frozenset()):
        """Recognize an unwritten pointer slot in this function's frame.

        The points-to convention treats an uninitialized local pointer as
        an uninitialized local pointer contributes an empty target
        alternative.  This is deliberately narrower than Unknown: only an
        exact negative stack-frame read from the entry memory qualifies.
        """

        if reference in seen:
            return False
        seen = seen | {reference}
        engine = self.port.engine
        node = engine.dag.nodes[reference]
        if node.op == SymbolicOp.COPY:
            return self.uninitialized_frame_pointer(node.operands[0], seen)
        if node.op != SymbolicOp.MEMORY_READ or node.state != self.initial.memory:
            return False
        location = engine.locations.get(node.location)
        if (
                location is None
                or location.object_id is None
                or location.offset_lower is None
                or location.offset_lower != location.offset_upper):
            return False
        root = engine.roots.get(location.object_id)
        if root is None or root.region != "stack":
            return False
        modulus = 1 << engine.architecture.pointer_bits
        signed_offset = (
            (location.offset_lower + modulus // 2) % modulus
            - modulus // 2
        )
        return signed_offset < 0
