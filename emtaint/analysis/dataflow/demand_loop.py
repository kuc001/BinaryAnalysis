"""Legacy-compatible loop summaries behind a composable resolver."""

from emtaint.core.contracts import Constant, ValueType
from emtaint.ir.canonical import Compute, ReadRegister, WriteRegister
from emtaint.memory import SymbolicOp


class LegacyLoopSummarizer:
    """Preserve the old single-stride DDG recurrence abstraction."""

    def __init__(self, owner) -> None:
        self.owner = owner

    def linear_register(
        self, operand, name: str, seen: frozenset[str] = frozenset()
    ):
        """Express a CIR value as coefficient*register+constant."""

        demand = self.owner
        if isinstance(operand, Constant):
            return 0, operand.value, ()
        if operand.id in seen or operand.id not in demand.defs:
            return None
        block, index, effect = demand.defs[operand.id]
        seen = seen | {operand.id}
        if isinstance(effect, ReadRegister):
            if effect.source.register == name:
                return 1, 0, ((block, index),)
            return None
        if not isinstance(effect, Compute):
            return None
        if effect.op.value == "copy":
            return self.linear_register(effect.args[0], name, seen)
        if effect.op.value not in ("add", "sub"):
            return None
        left, right = (
            self.linear_register(argument, name, seen)
            for argument in effect.args
        )
        if left is None or right is None:
            return None
        sign = 1 if effect.op.value == "add" else -1
        return (
            left[0] + sign * right[0],
            left[1] + sign * right[1],
            left[2] + right[2],
        )

    def increments(self, name: str, width: int):
        """Find real reaching-definition cycles with a nonzero stride."""

        demand = self.owner
        if name in demand.increment_cache:
            return demand.increment_cache[name]
        result = {}
        for block in demand.function.blocks:
            for index, effect in enumerate(block.effects):
                if (
                    not isinstance(effect, WriteRegister)
                    or effect.target.register != name
                    or getattr(effect.guard, "value", None) is not True
                ):
                    continue
                affine = self.linear_register(effect.value, name)
                if (
                    affine is None
                    or affine[0] != 1
                    or len(affine[2]) != 1
                ):
                    continue
                stride = affine[1] % (1 << width)
                if not stride:
                    continue
                point = affine[2][0]
                definitions, _ = demand.reaching(
                    point[0], point[1], name
                )
                if (block.id, index + 1) in definitions:
                    result[block.id, index + 1] = stride, point
        demand.increment_cache[name] = result
        return result

    def induction(
        self,
        block,
        index: int,
        name: str,
        width: int,
        depth: int,
    ):
        """Return the legacy base and base+i*stride alternatives."""

        demand = self.owner
        increments = self.increments(name, width)
        if not increments:
            return None
        definitions, entry = demand.reaching(block, index, name)
        pending = list(definitions)
        seen = set()
        bases = set()
        strides = set()
        while pending:
            definition = pending.pop()
            if definition in seen:
                continue
            seen.add(definition)
            if definition in increments:
                stride, point = increments[definition]
                strides.add(stride)
                incoming, at_entry = demand.reaching(
                    point[0], point[1], name
                )
                entry |= at_entry
                pending.extend(incoming)
            else:
                bases.add(definition)
        if len(strides) != 1 or not (bases or entry):
            return None
        origin = demand.blocks[block].effects[0].origin
        value_type = ValueType.bv(width)
        values = []
        for source, cutoff in sorted(
            bases, key=lambda item: (item[0].token, item[1])
        ):
            values.extend(
                demand.register(
                    source, cutoff, name, width, depth + 1
                )
            )
        if entry:
            values.append(
                dict(demand.initial.registers).get(name)
                or demand.port.symbol(
                    "entry:" + name, value_type, origin
                )
            )
        stride = next(iter(strides))
        variable = demand.port.symbol("i", value_type, origin)
        delta = demand.port.operation(
            SymbolicOp.MUL,
            value_type,
            (
                variable,
                demand.port.constant(stride, value_type, origin),
            ),
            origin,
        )
        expanded = tuple(
            demand.port.operation(
                SymbolicOp.ADD, value_type, (base, delta), origin
            )
            for base in values
        )
        demand.rules.add(
            "legacy.label_inc_flag_in_loop/DDG + "
            "_summary_variable_in_loop"
        )
        return demand.union((values, expanded))

    def affine(self, reference, variable):
        """Project an SSE expression into coefficient*variable+constant."""

        demand = self.owner
        if reference == variable:
            return 1, 0
        dag = demand.port.engine.dag
        node = dag.nodes[reference]
        constant = demand.port.concrete(reference)
        if type(constant) is int:
            return 0, constant
        if node.op == SymbolicOp.COPY:
            return self.affine(node.operands[0], variable)
        if node.op not in (
            SymbolicOp.ADD,
            SymbolicOp.SUB,
            SymbolicOp.MUL,
        ):
            return None
        left, right = (
            self.affine(operand, variable) for operand in node.operands
        )
        if left is None or right is None:
            return None
        if node.op == SymbolicOp.ADD:
            return left[0] + right[0], left[1] + right[1]
        if node.op == SymbolicOp.SUB:
            return left[0] - right[0], left[1] - right[1]
        if left[0] and right[0]:
            return None
        return (
            left[0] * right[1] + right[0] * left[1],
            left[1] * right[1],
        )

