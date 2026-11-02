"""Legacy AST access is confined to compat; all returned values are pure IDs.

Legacy Store(address,width) is a trace marker, not a value-bearing write.
Importing it without an explicit store value/order is always unsupported.
"""
from dataclasses import dataclass
from emtaint.core.contracts import ValueType, UnsupportedSemantics
from emtaint.memory import Offset, Deref, SymbolicOp


@dataclass(frozen=True)
class LegacySSEView:
    value: object
    alias_id: int
    trace_direction: str | None
    data_type: str | None
    source_provenance: tuple[str, ...]
    action_count: int


@dataclass(frozen=True)
class LegacyAstPacket:
    """Validated pure transport of a legacy characterization AST, never native."""
    op: str
    width: int
    args: tuple

    def size(self): return self.width

    @classmethod
    def from_dict(cls, value, depth=0):
        if depth > 64 or set(value) != {'op', 'width', 'args'}:
            raise ValueError('Invalid legacy AST packet/depth')
        if type(value['width']) is not int or not 1 <= value['width'] <= 4096:
            raise ValueError('Invalid packet bit width')
        if value['op'] not in ('BVS', 'BVV', 'Load', 'Store', '__add__', '__sub__', '__mul__', '__and__', '__or__', '__xor__'):
            raise ValueError('Unsupported legacy AST packet opcode')
        if type(value['args']) is not list: raise TypeError('Packet argument list required')
        args=tuple(cls.from_dict(x, depth+1) if isinstance(x, dict) else x for x in value['args'])
        if any(x is not None and not isinstance(x, (cls, str, int, bool)) for x in args): raise ValueError('Invalid packet argument')
        op=value['op']
        if op=='BVS' and (not args or type(args[0]) is not str): raise ValueError('BVS name required')
        if op=='BVS':
            supported=(len(args)==1 or len(args)==2 and args[1]==value['width'] or
                len(args)==7 and args[1:]==(None, None, None, False, False, None))
            if not supported: raise ValueError('Bounded/strided/VSA BVS packets are unsupported')
        if op=='BVV' and (not args or type(args[0]) is not int or not 0 <= args[0] < (1 << value['width'])):
            raise ValueError('BVV literal/width mismatch')
        if op in ('Load', 'Store') and (len(args)!=1 or not isinstance(args[0], cls)):
            raise ValueError('Legacy marker requires one address AST')
        if op.startswith('__') and (len(args)!=2 or any(not isinstance(x, cls) for x in args)):
            raise ValueError('Legacy binary AST requires two operands')
        return cls(value['op'], value['width'], args)


class LegacySSEAdapter:
    def __init__(self, engine, bindings, endian, origin, max_nodes=10000):
        self.engine, self.bindings, self.endian, self.origin = engine, dict(bindings), endian, origin
        self.max_nodes = max_nodes

    def access_path(self, ast):
        segments, steps = [], 0
        current = ast
        width = ast.size()
        while True:
            steps += 1
            if steps > self.max_nodes: raise UnsupportedSemantics('Legacy path extraction budget exceeded')
            op = current.op
            if getattr(current, 'annotations', ()): raise UnsupportedSemantics('Annotated legacy address requires explicit policy')
            if op == 'BVS':
                name = current.args[0]
                if name not in self.bindings: raise UnsupportedSemantics('Legacy symbol lacks stable root binding: '+name)
                root = self.bindings[name]
                return self.engine.path(root, tuple(reversed(segments)), width, self.endian, self.origin)
            if op == 'Load':
                segments.append(Deref(current.args[0].size(), current.size(), self.endian))
                current = current.args[0]
            elif op in ('__add__', '__sub__') and len(current.args)==2 and current.args[1].op=='BVV':
                amount = current.args[1].args[0]
                segments.append(Offset(amount if op=='__add__' else -amount))
                current = current.args[0]
            elif op == 'Store':
                raise UnsupportedSemantics('Legacy Store marker has no value/order; explicit write required')
            else: raise UnsupportedSemantics('Unnormalized legacy address: '+op)

    def import_value(self, ast, state):
        done, stack, steps = {}, [(ast, False)], 0
        binary = {'__add__':SymbolicOp.ADD, '__sub__':SymbolicOp.SUB, '__mul__':SymbolicOp.MUL,
                  '__and__':SymbolicOp.AND, '__or__':SymbolicOp.OR, '__xor__':SymbolicOp.XOR}
        while stack:
            node, ready = stack.pop()
            identity=id(node)
            if identity in done: continue
            steps += 1
            if steps > self.max_nodes: raise UnsupportedSemantics('Legacy value extraction budget exceeded')
            width = node.size()
            if getattr(node, 'annotations', ()): raise UnsupportedSemantics('Annotated legacy SSE requires explicit policy')
            if node.op=='BVS':
                args=tuple(node.args)
                if not (len(args)==1 or len(args)==2 and args[1]==width or
                        len(args)==7 and args[1:]==(None, None, None, False, False, None)):
                    raise UnsupportedSemantics('Bounded/strided/VSA legacy symbol is unsupported')
            if node.op=='Load':
                # The final Deref is the read being imported. Earlier derefs
                # remain path operations and resolve to unknown storage.
                path = self.access_path(node)
                address = self.engine.path(path.root, path.segments[:-1], width, self.endian, self.origin)
                loc = self.engine.location_from_path(address)
                done[identity] = self.engine.load(state, loc, origin=self.origin)
            elif node.op=='Store':
                raise UnsupportedSemantics('Raw Store markers cannot be lowered as writes or solver terms')
            elif node.op=='BVV': done[identity] = self.engine.dag.constant(node.args[0], width, self.origin)
            elif node.op=='BVS': done[identity] = self.engine.dag.symbol(node.args[0], ValueType.bv(width), self.origin)
            elif node.op in binary and len(node.args)==2:
                if not ready:
                    stack.append((node, True))
                    stack.extend((child, False) for child in node.args)
                else: done[identity] = self.engine.dag.operation(binary[node.op], ValueType.bv(width),
                    tuple(done[id(child)] for child in node.args), self.origin)
            else: raise UnsupportedSemantics('Legacy value opcode unsupported: '+node.op)
        return done[id(ast)]

    def capture(self, trace, state):
        expr = trace.expr if hasattr(trace, 'expr') else trace
        value = self.import_value(expr.ast, state)
        provenance = tuple(str(x) for x in (getattr(expr, 'source', None), getattr(expr, 'taint_source', None)) if x is not None)
        return LegacySSEView(value, expr.alias_id, expr.trace_dir, expr.data_type, provenance, len(expr.sim_actions))
