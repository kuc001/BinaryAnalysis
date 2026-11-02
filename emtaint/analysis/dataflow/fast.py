"""Backward def-use for characterized w/p/wo/wu and port-based memory uses.

Unlike legacy ignored indirect-memory branches, missing memory proof is visible.
"""
from dataclasses import dataclass
from emtaint.core.contracts import Assessment
from emtaint.ir.canonical import Compute, ReadRegister, WriteRegister, LoadEffect, StoreEffect, RegisterWritePolicy
from emtaint.memory import AliasKind
from emtaint.memory.engine import combine, over


@dataclass(frozen=True)
class SliceResult:
    inputs: tuple[str, ...]
    origins: tuple[str, ...]
    dependencies: tuple[tuple[str, str], ...]
    assessment: Assessment


class CIRFastDataFlow:
    def slice(self, effects, outputs, port=None, state=None, bindings=None):
        live=set(outputs)
        origins=[]
        dependencies=[]
        memory=[]
        assessments=[]
        def add(operand):
            if hasattr(operand, 'id'):live.add(operand.id)
        for effect in reversed(tuple(effects)):
            used=False
            if isinstance(effect, Compute) and effect.result.id in live:
                live.remove(effect.result.id)
                for arg in effect.args:add(arg)
                used=True
            elif isinstance(effect, ReadRegister) and effect.result.id in live:
                live.remove(effect.result.id)
                live.add('reg:'+effect.source.register)
                used=True
            elif isinstance(effect, WriteRegister) and 'reg:'+effect.target.register in live:
                if effect.policy==RegisterWritePolicy.FULL and getattr(effect.guard, 'value', None) is True:
                    live.remove('reg:'+effect.target.register)
                else:assessments.append(over('Partial/guarded register definition retains earlier uses'))
                add(effect.value)
                add(effect.guard)
                used=True
            elif isinstance(effect, LoadEffect) and effect.result.id in live:
                live.remove(effect.result.id)
                add(effect.address)
                add(effect.guard)
                used=True
                if port is not None:
                    loc=port.location(effect.address, bindings or {}, {}, effect.width_bits, effect.endian, effect.origin)
                    memory.append(loc)
                else:assessments.append(over('Memory dependency requires MemoryQueryPort', True))
            elif isinstance(effect, StoreEffect) and memory:
                loc=port.location(effect.address, bindings or {}, {}, effect.width_bits, effect.endian, effect.origin)
                remaining=[]
                for demand in memory:
                    alias=port.alias(state, loc, demand)
                    if alias.kind!=AliasKind.NO:
                        add(effect.value)
                        add(effect.address)
                        add(effect.guard)
                        used=True
                        if alias.kind!=AliasKind.MUST or getattr(effect.guard, 'value', None) is not True:remaining.append(demand)
                    else:remaining.append(demand)
                memory=remaining
            elif not isinstance(effect, (Compute, ReadRegister, WriteRegister, LoadEffect, StoreEffect)):
                assessments.append(over('Backward family not yet ported: '+type(effect).__name__, True))
            if used:
                if origins:dependencies.append((effect.origin, origins[-1]))
                origins.append(effect.origin)
        if memory:assessments.append(over('Memory demands reach function entry', True))
        return SliceResult(tuple(sorted(live)), tuple(reversed(tuple(dict.fromkeys(origins)))), tuple(dependencies), combine(assessments))
