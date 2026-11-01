"""Hash-consed typed SSE DAG with nonrecursive, memoized lazy substitution."""
from dataclasses import dataclass
from emtaint.core.contracts import (ValueType, SymbolicExprId, validate_value_operation,
    same_scope, TypeKind)
from emtaint.memory.state import SymbolicNode, SymbolicOp


@dataclass(frozen=True)
class LazySubstitution:
    root: SymbolicExprId
    replacements: tuple[tuple[SymbolicExprId, SymbolicExprId], ...]


class SymbolicExprDAG:
    def __init__(self, scope, accounting):
        self.scope, self.accounting = scope, accounting
        self.nodes, self._intern, self._substitution_memo = {}, {}, {}
        self._constant_memo = {}

    @staticmethod
    def _key(node):
        return (node.type, node.op, node.operands, node.origin, node.value,
                node.state, node.location, node.params)

    def restore(self, nodes):
        self._constant_memo.clear()
        for node in nodes:
            same_scope(self.scope, node.id)
            self.accounting.check('sse_nodes', len(self.nodes) + 1)
            self.nodes[node.id] = node
            self._intern[self._key(node)] = node.id
        self.accounting.set('sse_nodes', len(self.nodes))

    def make(self, type_, op, operands=(), origin=None, value=None, state=None, location=None, params=()):
        if op not in (SymbolicOp.CONSTANT, SymbolicOp.SYMBOL, SymbolicOp.UNKNOWN, SymbolicOp.MEMORY_READ):
            validate_value_operation(op.value, type_, [self.nodes[x].type for x in operands], params)
        key = (type_, op, tuple(operands), origin, value, state, location, tuple(params))
        if key in self._intern:
            return self._intern[key]
        self.accounting.check('sse_nodes', len(self.nodes) + 1)
        n = len(self.nodes)
        while SymbolicExprId(self.scope, 'sse-' + str(n)) in self.nodes:
            n += 1
        ref = SymbolicExprId(self.scope, 'sse-' + str(n))
        node = SymbolicNode(ref, type_, op, tuple(operands), origin, value, state, location, tuple(params))
        self.nodes[ref] = node
        self._intern[key] = ref
        self.accounting.set('sse_nodes', len(self.nodes))
        return ref

    def constant(self, value, width, origin):
        return self.make(ValueType.bv(width), SymbolicOp.CONSTANT, origin=origin, value=value % (1 << width))

    def boolean(self, value, origin):
        if type(value) is not bool:
            raise TypeError('Explicit boolean required')
        return self.make(ValueType.boolean(), SymbolicOp.CONSTANT, origin=origin, value=value)

    def symbol(self, name, type_, origin):
        return self.make(type_, SymbolicOp.SYMBOL, origin=origin, value=name)

    def operation(self, op, type_, operands, origin, params=()):
        # Constant folding uses target modular BV arithmetic only.
        if op == SymbolicOp.IF:
            validate_value_operation(op.value,type_,[self.nodes[x].type for x in operands],params)
            guard=self.constant_value(operands[0])
            selected=operands[1] if guard is True else operands[2] if guard is False else operands[1] if operands[1]==operands[2] else None
            if selected is not None:
                return self.operation(SymbolicOp.COPY,type_,(selected,),origin)
        ref = self.make(type_, op, operands, origin, params=params)
        value = self.constant_value(ref)
        if value is not None:
            return (self.boolean(value, origin) if type_.kind == TypeKind.BOOL
                    else self.make(type_, SymbolicOp.CONSTANT, origin=origin, value=value))
        return ref

    def substitute(self, root, replacements):
        for old, new in replacements.items():
            same_scope(self.scope, old, new)
            if self.nodes[old].type != self.nodes[new].type:
                raise ValueError('Substitution sort mismatch')
        return LazySubstitution(root, tuple(replacements.items()))

    def materialize(self, lazy):
        if lazy in self._substitution_memo:
            return self._substitution_memo[lazy]
        self.accounting.check('sse_nodes',len(self.nodes)+len(self._substitution_memo)+1)
        replacements = dict(lazy.replacements)
        done, stack = dict(replacements), [(lazy.root, False)]
        while stack:
            ref, ready = stack.pop()
            if ref in done:
                continue
            node = self.nodes[ref]
            if not ready and node.operands:
                stack.append((ref, True))
                stack.extend((x, False) for x in node.operands if x not in done)
                continue
            # MemoryRead is a leaf: substitution cannot cross memory versions.
            done[ref] = (self.operation(node.op, node.type, tuple(done[x] for x in node.operands),
                                       node.origin, node.params) if node.operands else ref)
        self._substitution_memo[lazy] = done[lazy.root]
        return done[lazy.root]

    def constant_value(self, root):
        done, stack = self._constant_memo, [(root, False)]
        while stack:
            ref, ready = stack.pop()
            if ref in done:
                continue
            n = self.nodes[ref]
            if not ready and n.operands:
                stack.append((ref, True))
                stack.extend((x, False) for x in n.operands if x not in done)
                continue
            a = [done[x] for x in n.operands]
            if n.op == SymbolicOp.CONSTANT:
                val = n.value
            elif n.op == SymbolicOp.IF:
                val = a[1] if a[0] is True else a[2] if a[0] is False else a[1] if a[1] == a[2] else None
            elif n.op == SymbolicOp.COPY:
                val = a[0]
            elif not a or any(x is None for x in a):
                val = None
            else:
                val = self._calculate(n, a)
            if val is not None and n.type.kind != TypeKind.BOOL:
                val %= (1 << n.type.bits)
            done[ref] = val
        return done[root]

    def _calculate(self, n, a):
        op = n.op
        if op == SymbolicOp.ADD: return a[0] + a[1]
        if op == SymbolicOp.SUB: return a[0] - a[1]
        if op == SymbolicOp.MUL: return a[0] * a[1]
        if op == SymbolicOp.AND: return a[0] & a[1]
        if op == SymbolicOp.OR: return a[0] | a[1]
        if op == SymbolicOp.XOR: return a[0] ^ a[1]
        if op == SymbolicOp.EQ: return a[0] == a[1]
        if op == SymbolicOp.ULT: return a[0] < a[1]
        if op == SymbolicOp.SLT:
            w = self.nodes[n.operands[0]].type.bits
            signed = lambda v: v - (1 << w) if v & (1 << (w-1)) else v
            return signed(a[0]) < signed(a[1])
        if op == SymbolicOp.NOT: return not a[0] if n.type.kind == TypeKind.BOOL else ~a[0]
        if op == SymbolicOp.EXTRACT: return (a[0] >> n.params[1]) & ((1 << n.type.bits)-1)
        if op == SymbolicOp.ZERO_EXTEND: return a[0]
        if op == SymbolicOp.SIGN_EXTEND:
            w = self.nodes[n.operands[0]].type.bits
            return a[0] - (1 << w) if a[0] & (1 << (w-1)) else a[0]
        if op == SymbolicOp.CONCAT:
            value = 0
            for ref, item in zip(n.operands, a): value = (value << self.nodes[ref].type.bits) | item
            return value
        return None
