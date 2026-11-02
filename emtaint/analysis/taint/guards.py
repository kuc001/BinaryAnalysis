"""FastSearch._add_taint_constraint policy; a filter is not an SMT proof."""

from dataclasses import dataclass
from typing import Protocol

from emtaint.core.contracts import Constant, ValueRef
from emtaint.ir.canonical import Compute, ValueOp


class _BitType(Protocol):
    """Expose the bit width required from a recipe value type."""

    bits: int


class _RecipeNode(Protocol):
    """Structural view of the recipe nodes consumed by the legacy policy."""

    type: _BitType
    op: str
    operands: tuple[int, ...]
    value: object


class _Recipe(Protocol):
    """Structural view of a bounded scalar recipe used for guard recognition."""

    nodes: tuple[_RecipeNode, ...]
    returns: tuple[int, ...]
    argument_uses: tuple[int, ...]


def unit_product_arguments(recipe: _Recipe) -> tuple[int, int] | None:
    """Identify a 32-bit ``1 * arg * arg`` length without evaluating it.

    Other arithmetic, casts, widths, or additional factors cannot inherit a
    caller's two independent branch bounds by this rule.
    """
    nodes = recipe.nodes
    if len(recipe.returns) != 1:
        return None
    factors = []
    active = set()

    def visit(index: int) -> bool:
        if not isinstance(index, int) or index < 0 or index >= len(nodes):
            return False
        if index in active:
            return False
        active.add(index)
        node = nodes[index]
        if node.type.bits != 32:
            active.remove(index)
            return False
        if node.op == 'mul' and len(node.operands) == 2:
            result = all(visit(child) for child in node.operands)
            active.remove(index)
            return result
        if node.operands:
            active.remove(index)
            return False
        if node.op == 'constant' and node.value == 1:
            factors.append(('constant', 1))
            active.remove(index)
            return True
        if node.op == 'argument' and type(node.value) is int:
            factors.append(('argument', node.value))
            active.remove(index)
            return True
        active.remove(index)
        return False

    if not visit(recipe.returns[0]):
        return None
    arguments = tuple(value for kind, value in factors if kind == 'argument')
    if factors.count(('constant', 1)) != 1 or len(arguments) != 2:
        return None
    if len(factors) != 3 or arguments[0] == arguments[1]:
        return None
    if tuple(sorted(arguments)) != tuple(sorted(recipe.argument_uses)):
        return None
    return arguments


@dataclass(frozen=True)
class ConstraintDecision:
    """Describe whether a legacy branch kills taint or adds scalar bounds."""

    kill: bool = False
    constraints: tuple[int, ...] = ()
    classification: str = 'legacy-constraint-heuristic'


def legacy_constraint(
    kind: int,
    operation: str,
    bound: int,
    *,
    pointer: bool = True,
    symbol: bool = True,
) -> ConstraintDecision:
    """Apply the preserved legacy scalar constraint classification policy."""

    if kind in (4, 5) and operation in ('eq', 'le', 'lt') and bound != 0xffffffff:
        return ConstraintDecision(constraints=(bound,))
    kill = (
        (kind == 2 and operation == 'eq' and bound == 0)
        or (kind == 1 and operation != 'eq' and bound == 0)
        or (kind == 6 and operation == 'eq' and bound == 0 and not pointer)
        or (kind == 0 and operation == 'eq' and bound == 0 and symbol)
    )
    return ConstraintDecision(kill=kill)


@dataclass(frozen=True)
class UnsignedHiGuard:
    """The true edge is ``left > right`` at the stated bit width."""

    left: ValueRef
    right: ValueRef | Constant
    bits: int

    def relation(self, true_edge: bool) -> str:
        """Return the exact unsigned relation for the selected CFG edge."""
        return 'ugt' if true_edge else 'ule'


@dataclass(frozen=True)
class EqualityGuard:
    """The true edge proves equal-width bitvector equality."""

    left: ValueRef
    right: ValueRef | Constant
    bits: int

    def relation(self, true_edge: bool) -> str:
        """Return equality or inequality for the selected CFG edge."""

        return 'eq' if true_edge else 'ne'


def arm_zero_flag_equal(effects: tuple, condition: ValueRef | Constant) -> EqualityGuard | None:
    """Recognize the ARM EQ flag chain only when its subtraction is exact."""
    definitions={effect.result.id:effect for effect in effects if isinstance(effect,Compute)}

    def unwrap(value):
        for _ in range(12):
            effect=definitions.get(value.id) if isinstance(value,ValueRef) else None
            if effect is None:return value
            if effect.op==ValueOp.COPY:
                value=effect.args[0];continue
            if effect.op==ValueOp.EXTRACT and effect.params==(0,0):
                value=effect.args[0];continue
            return value
        return value

    def match_equal(value,constant):
        effect=definitions.get(value.id) if isinstance(value,ValueRef) else None
        if effect is None or effect.op!=ValueOp.EQ:return None
        first,second=effect.args
        if isinstance(second,Constant) and second.value==constant:return unwrap(first)
        if isinstance(first,Constant) and first.value==constant:return unwrap(second)
        return None

    bit=match_equal(unwrap(condition),1)
    choice=definitions.get(bit.id) if isinstance(bit,ValueRef) else None
    if choice is None or choice.op!=ValueOp.IF:return None
    if not (isinstance(choice.args[1],Constant) and choice.args[1].value==1 and
            isinstance(choice.args[2],Constant) and choice.args[2].value==0):return None
    difference=match_equal(unwrap(choice.args[0]),0)
    subtract=definitions.get(difference.id) if isinstance(difference,ValueRef) else None
    if subtract is None or subtract.op!=ValueOp.SUB:return None
    left,right=subtract.args
    if not isinstance(left,ValueRef) or left.type.bits!=right.type.bits:return None
    return EqualityGuard(left,right,left.type.bits)


def arm_unsigned_hi(effects: tuple, condition: ValueRef | Constant) -> UnsignedHiGuard | None:
    """Recognize VEX ARM HI flags without treating an unknown branch as false.

    HI is ``not (x <u y) and not (x == y)``. The false edge therefore has
    ``x <=u y``. Require both comparisons to use the same 32-bit operands;
    nearby signed or mismatched flag expressions remain unsupported.
    """
    definitions={effect.result.id:effect for effect in effects if isinstance(effect,Compute)}

    def definition(value):
        return definitions.get(value.id) if isinstance(value,ValueRef) else None

    def literal(value,number):
        return isinstance(value,Constant) and value.value==number

    def unwrap(value):
        for _ in range(12):
            effect=definition(value)
            if effect is None:return value
            if effect.op==ValueOp.COPY:
                value=effect.args[0];continue
            if effect.op==ValueOp.EXTRACT and effect.params==(0,0):
                value=effect.args[0];continue
            return value
        return value

    def equality_to(value,number):
        effect=definition(unwrap(value))
        if effect is None or effect.op!=ValueOp.EQ:return None
        first,second=effect.args
        if literal(second,number):return unwrap(first)
        if literal(first,number):return unwrap(second)
        return None

    def greater_equal_part(value):
        effect=definition(unwrap(value))
        if effect is None or effect.op!=ValueOp.IF or not literal(effect.args[1],0) or not literal(effect.args[2],1):return None
        compare=definition(unwrap(effect.args[0]))
        return compare.args if compare is not None and compare.op==ValueOp.ULT else None

    def not_equal_part(value):
        effect=definition(unwrap(value))
        if effect is None or effect.op!=ValueOp.XOR:return None
        first,second=effect.args
        inner=first if literal(second,1) else second if literal(first,1) else None
        choice=definition(unwrap(inner)) if inner is not None else None
        if choice is None or choice.op!=ValueOp.IF or not literal(choice.args[1],1) or not literal(choice.args[2],0):return None
        difference=equality_to(choice.args[0],0)
        subtract=definition(difference) if difference is not None else None
        return subtract.args if subtract is not None and subtract.op==ValueOp.SUB else None

    body=equality_to(condition,1)
    combined=definition(body) if body is not None else None
    if combined is None or combined.op!=ValueOp.AND:return None
    first,second=combined.args
    pairs=((greater_equal_part(first),not_equal_part(second)),
           (greater_equal_part(second),not_equal_part(first)))
    for unsigned,unequal in pairs:
        if unsigned is None or unequal is None or unsigned!=unequal:continue
        left,right=unsigned
        if not isinstance(left,ValueRef) or left.type.bits!=32 or right.type.bits!=32:continue
        return UnsignedHiGuard(left,right,32)
    return None
