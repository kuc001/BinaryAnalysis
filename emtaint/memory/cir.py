"""Bounded CIR memory-effect harness, not a CFG or interprocedural dataflow pass.

Address provenance is seeded explicitly. Unresolved numeric addresses become
unknown locations; no guessed pointer-to-object mapping is introduced here.
"""
from emtaint.core.contracts import Constant, TypeKind, ValueType, UnsupportedSemantics
from emtaint.ir.canonical import Compute, LoadEffect, StoreEffect, HavocEffect, UnknownEffect, CallEffect
from .state import SymbolicOp
from .engine import over


class MemoryEffectInterpreter:
    def __init__(self, engine, values=None, addresses=None):
        self.engine=engine
        self.values=dict(values or {})
        self.addresses=dict(addresses or {})
        self.steps=0

    def operand(self, operand, origin):
        if isinstance(operand, Constant):
            return self.engine.dag.make(operand.type, SymbolicOp.CONSTANT, origin=origin, value=operand.value)
        if operand.id not in self.values:
            raise UnsupportedSemantics('CIR value must be defined or explicitly seeded: '+operand.id)
        result=self.values[operand.id]
        if self.engine.dag.nodes[result].type!=operand.type: raise ValueError('CIR seed type mismatch')
        return result

    def location(self, address, width, endian, origin):
        binding=self.addresses.get(address.id) if hasattr(address, 'id') else None
        if binding is None:
            return self.engine.location(None, None, width, endian, origin)
        root, offset=binding
        return self.engine.location(root, offset, width, endian, origin)

    def apply(self, state, effect):
        self.engine.accounting.charge('worklist_iterations')
        self.steps+=1
        e=self.engine
        d=e.dag
        origin=effect.origin
        if isinstance(effect, Compute):
            args=tuple(self.operand(x, origin) for x in effect.args)
            prior_binding=self.addresses.get(effect.args[0].id) if effect.args and hasattr(effect.args[0], 'id') else None
            result=d.operation(SymbolicOp(effect.op.value), effect.result.type, args, origin, effect.params)
            self.values[effect.result.id]=result
            self.addresses.pop(effect.result.id, None)
            if effect.op.value=='copy' and hasattr(effect.args[0], 'id'):
                binding=prior_binding
                if binding is not None: self.addresses[effect.result.id]=binding
            elif effect.op.value in ('add', 'sub') and hasattr(effect.args[0], 'id'):
                binding=prior_binding
                offset=d.constant_value(args[1])
                if binding is not None and offset is not None and effect.result.type.kind==TypeKind.POINTER:
                    root, base=binding
                    delta=offset if effect.op.value=='add' else -offset
                    self.addresses[effect.result.id]=(root, (base+delta)%(1<<e.architecture.pointer_bits))
            return state
        if isinstance(effect, StoreEffect):
            return e.store(state, self.location(effect.address, effect.width_bits, effect.endian, origin),
                self.operand(effect.value, origin), self.operand(effect.guard, origin), origin)
        if isinstance(effect, LoadEffect):
            guard=self.operand(effect.guard, origin)
            loc=self.location(effect.address, effect.width_bits, effect.endian, origin)
            if d.constant_value(guard) is True:
                result=e.load(state, loc, origin=origin)
                if effect.result.type.kind==TypeKind.POINTER:
                    zero=d.make(effect.result.type, SymbolicOp.CONSTANT, origin=origin, value=0)
                    result=d.operation(SymbolicOp.ADD, effect.result.type, (zero, result), origin)
                self.values[effect.result.id]=result
                self.addresses.pop(effect.result.id, None)
                return state
            old=self.values.get(effect.result.id)
            if old is None:
                old=d.make(ValueType.bv(effect.width_bits), SymbolicOp.UNKNOWN, origin=origin,
                           value='Load result undefined on false guard')
            elif d.nodes[old].type.kind==TypeKind.POINTER:
                zero=d.make(d.nodes[old].type, SymbolicOp.CONSTANT, origin=origin, value=0)
                old=d.operation(SymbolicOp.SUB, ValueType.bv(effect.width_bits), (old, zero), origin)
            result=e.guarded_load(state, loc, guard, old, origin)
            if effect.result.type.kind==TypeKind.POINTER:
                zero=d.make(effect.result.type, SymbolicOp.CONSTANT, origin=origin, value=0)
                result=d.operation(SymbolicOp.ADD, effect.result.type, (zero, result), origin)
            self.values[effect.result.id]=result
            self.addresses.pop(effect.result.id, None)
            return state
        if isinstance(effect, UnknownEffect):
            e._notes.append(over(effect.reason, True))
            return e.havoc(state, effect.may_write_regions, effect.reason, origin) if effect.may_write_regions else state
        if isinstance(effect, (CallEffect, HavocEffect)):
            regions=effect.footprint.write_regions if isinstance(effect, CallEffect) else effect.regions
            guard=self.operand(effect.guard, origin)
            if d.constant_value(guard) is False: return state
            if isinstance(effect, CallEffect):
                for result in effect.results:
                    self.values[result.id]=d.make(result.type, SymbolicOp.UNKNOWN, origin=origin, value='Call result without summary')
                    self.addresses.pop(result.id, None)
            if regions:
                return e.havoc(state, regions, 'CIR call/explicit havoc', origin, guard)
            return state
        raise UnsupportedSemantics('P5 bounded harness does not execute '+type(effect).__name__)

    def run(self, effects, state=None):
        current=self.engine.initial if state is None else state
        for effect in effects: current=self.apply(current, effect)
        return current
