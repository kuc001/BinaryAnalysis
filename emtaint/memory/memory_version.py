"""Demand-driven byte definition resolution into the shared pure-value DAG.

May-alias conditions are nondeterministic predicates, a conservative upper
approximation. They are intentionally not claimed as an exact alias solution.
"""
from dataclasses import replace
from emtaint.core import Endian
from emtaint.core.contracts import ValueType, TypeKind
from .state import SymbolicOp, InitialMemory, WriteMemory, JoinMemory, HavocMemory, AliasKind, UpdateKind
from .policies import BudgetExceeded
from .engine import token, over
from .read_index import records_for


class DefinitionResolver:
    def __init__(self, engine, budget):
        self.e, self.d, self.budget = engine, engine.dag, budget
        self.memo, self.byte_memo, self.definitions = {}, {}, set()
        self.steps, self.assessments = 0, []
        self.read_dependencies={}
        self._pure_refs=set()

    def step(self, depth):
        self.steps += 1
        self.e.accounting.charge('worklist_iterations')
        if self.steps > self.budget.max_steps:
            raise BudgetExceeded('worklist_iterations', self.budget.max_steps, self.steps)
        # Recursive implementation has an explicit bound before Python overflow.
        # The stored SSE/MemoryVersion DAG itself has no recursive Load expansion.
        if depth > 64:
            raise BudgetExceeded('worklist_iterations', 64, depth)

    def expression(self, ref, depth=0):
        if ref in self.memo: return self.memo[ref]
        pure_cache=self.e._pure_values if getattr(self.e, 'cache_resolutions', False) else None
        if pure_cache is not None and ref in pure_cache:
            self.step(depth)
            self.e._pure_value_hits+=1
            pure_cache.move_to_end(ref)
            value=pure_cache[ref]
            self.memo[ref]=value
            self._pure_refs.add(ref)
            return value
        self.step(depth)
        n = self.d.nodes[ref]
        if n.op == SymbolicOp.MEMORY_READ:
            loc = self.e.locations[n.location]
            self.assessments.append(loc.assessment)
            records=records_for(self.e.reads, ref)
            self.read_dependencies[ref]=records
            guards = {r.guard for r in records}
            if len(guards) > 1:
                raise ValueError('One MemoryRead ID cannot describe distinct guarded definitions')
            guard_ref = next(iter(guards), None)
            guard = self.guard(guard_ref, n.origin, depth)
            execute = self.d.constant_value(guard)
            undefined = None
            if execute is not True:
                undefined = self.d.symbol('nonexecuted-read-'+token(ref), n.type, n.origin)
                self.assessments.append(over('Guarded read value undefined when guard is false'))
            if execute is False:
                value = undefined
            else:
                values = [self.byte(n.state, loc, i, depth+1) for i in range(loc.width_bits//8)]
                if loc.endian == Endian.LITTLE: values.reverse()
                value = values[0] if len(values)==1 else self.d.operation(SymbolicOp.CONCAT, n.type, tuple(values), n.origin)
                if execute is not True: value = self.choose(guard, value, undefined, n.origin)
        elif n.operands:
            if n.op == SymbolicOp.IF:
                condition = self.expression(n.operands[0], depth+1)
                concrete = self.d.constant_value(condition)
                if concrete is not None:
                    selected=n.operands[1 if concrete else 2]
                    value = self.expression(selected, depth+1)
                    if n.operands[0] in self._pure_refs and selected in self._pure_refs:self._pure_refs.add(ref)
                else:
                    value = self.d.operation(n.op, n.type, (condition,
                        self.expression(n.operands[1], depth+1), self.expression(n.operands[2], depth+1)), n.origin, n.params)
                    if all(x in self._pure_refs for x in n.operands):self._pure_refs.add(ref)
            else:
                value = self.d.operation(n.op, n.type, tuple(self.expression(x, depth+1) for x in n.operands), n.origin, n.params)
                if all(x in self._pure_refs for x in n.operands):self._pure_refs.add(ref)
        else:
            value = ref
            self._pure_refs.add(ref)
        self.memo[ref] = value
        if pure_cache is not None and ref in self._pure_refs:
            pure_cache[ref]=value
            pure_cache.move_to_end(ref)
            if len(pure_cache)>4096:pure_cache.popitem(last=False)
        return value

    def boolean(self, name, origin):
        bit = self.d.symbol('choice-'+token(name), ValueType.bv(1), origin)
        return self.d.operation(SymbolicOp.EQ, ValueType.boolean(), (bit, self.d.constant(1, 1, origin)), origin)

    def choose(self, condition, yes, no, origin):
        if yes == no: return yes
        return self.d.operation(SymbolicOp.IF, self.d.nodes[yes].type, (condition, yes, no), origin)

    def guard(self, ref, origin, depth):
        return self.d.boolean(True, origin) if ref is None else self.expression(ref, depth+1)

    def byte_location(self, loc, index):
        mask = (1 << self.e.architecture.pointer_bits)-1
        lo = None if loc.offset_lower is None else (loc.offset_lower+index)&mask
        hi = None if loc.offset_upper is None else (loc.offset_upper+index)&mask
        if lo is not None and hi < lo: lo=hi=None
        assessment = loc.assessment if lo is not None else over('Wrapped or unbounded byte range', True)
        return replace(loc, offset_lower=lo, offset_upper=hi, width_bits=8, assessment=assessment)

    def byte(self, state, loc, index, depth=0):
        cell = self.byte_location(loc, index)
        # Endian and read width do not affect a physical byte's stable identity.
        identity = (cell.object_id, cell.offset_lower, cell.offset_upper, cell.address_space)
        if cell.object_id is None or cell.offset_lower is None: identity += (loc.id, index)
        key = (state, identity)
        if key in self.byte_memo: return self.byte_memo[key]
        skipped=[]
        while True:
            if key in self.byte_memo:
                result=self.byte_memo[key]
                for skipped_key in skipped:self.byte_memo[skipped_key]=result
                return result
            self.step(depth)
            definition=self.e.versions[state].definition
            if isinstance(definition, WriteMemory):
                guard=self.guard(definition.guard, definition.origin, depth)
                no_write=self.d.constant_value(guard) is False
                if not no_write:
                    no_write=self.e.resolve_alias(state, cell, self.e.locations[definition.location], self.budget).kind==AliasKind.NO
                if no_write:
                    skipped.append(key)
                    state=definition.parent
                    key=(state, identity)
                    continue
            break
        origin = definition.origin
        if isinstance(definition, InitialMemory):
            self.definitions.add(state)
            result = self.d.symbol('initial-byte-'+token((state, identity)), ValueType.bv(8), origin)
        elif isinstance(definition, WriteMemory):
            guard = self.guard(definition.guard, origin, depth)
            write_loc = self.e.locations[definition.location]
            candidates = []
            if self.d.constant_value(guard) is not False:
                count = write_loc.width_bits//8
                self.e.accounting.check('alias_candidates', count)
                self.e.accounting.counts['alias_candidates']=max(self.e.accounting.counts['alias_candidates'], count)
                if count > self.budget.max_alias_candidates:
                    raise BudgetExceeded('alias_candidates', self.budget.max_alias_candidates, count)
                for j in range(count):
                    alias = self.e.resolve_alias(state, cell, self.byte_location(write_loc, j), self.budget)
                    if alias.kind != AliasKind.NO: candidates.append((j, alias))
            if (len(candidates)==1 and candidates[0][1].kind == AliasKind.MUST
                    and definition.update == UpdateKind.STRONG and self.d.constant_value(guard) is True):
                j, _ = candidates[0]
                result = self.extract_byte(self.expression(definition.value, depth+1), write_loc, j, origin)
                self.definitions.add(state)
            else:
                result = self.byte(definition.parent, loc, index, depth+1)
                if candidates:
                    self.definitions.add(state)
                    value = self.expression(definition.value, depth+1)
                    for j, alias in candidates:
                        self.assessments.append(alias.assessment)
                        condition = guard
                        if definition.update == UpdateKind.WEAK:
                            self.assessments.append(over('Weak write may target another concrete location/instance'))
                            present=self.boolean((state, 'weak-write-target'), origin)
                            condition=self.d.operation(SymbolicOp.IF, ValueType.boolean(),
                                (guard, present, self.d.boolean(False, origin)), origin)
                        if alias.kind != AliasKind.MUST:
                            self.assessments.append(over('May-alias byte update retains all old/new choices', alias.kind==AliasKind.UNKNOWN))
                            may = self.boolean((state, identity, j, 'alias'), origin)
                            condition = self.d.operation(SymbolicOp.IF, ValueType.boolean(),
                                (condition, may, self.d.boolean(False, origin)), origin)
                        result = self.choose(condition, self.extract_byte(value, write_loc, j, origin), result, origin)
        elif isinstance(definition, HavocMemory):
            guard = self.guard(definition.guard, origin, depth)
            region = self.e.object_facts[cell.object_id].region if cell.object_id in self.e.object_facts else '*'
            affects = '*' in definition.regions or region == '*' or region in definition.regions
            if affects and self.d.constant_value(guard) is not False:
                self.definitions.add(state)
                self.assessments.append(over('Unknown side effect conservatively havocs byte', True))
                fresh = self.d.symbol('havoc-byte-'+token((state, identity)), ValueType.bv(8), origin)
                result = fresh if self.d.constant_value(guard) is True else self.choose(guard, fresh, self.byte(definition.parent, loc, index, depth+1), origin)
            else: result = self.byte(definition.parent, loc, index, depth+1)
        elif isinstance(definition, JoinMemory):
            self.definitions.add(state)
            self.assessments.append(over('Predecessor join; guarded union with unconstrained unreachable fallback'))
            result = self.d.symbol('join-fallback-'+token((state, identity)), ValueType.bv(8), origin)
            for i, item in reversed(tuple(enumerate(definition.inputs))):
                guard = self.boolean((state, 'predecessor', i), origin) if item.guard is None else self.guard(item.guard, origin, depth)
                if self.d.constant_value(guard) is False: continue
                value = self.byte(item.version, loc, index, depth+1)
                result = self.choose(guard, value, result, origin)
        else: raise TypeError('Unknown memory definition')
        self.byte_memo[key] = result
        for skipped_key in skipped:self.byte_memo[skipped_key]=result
        return result

    def extract_byte(self, value, location, index, origin):
        if self.d.nodes[value].type.kind == TypeKind.POINTER:
            pointer_type = self.d.nodes[value].type
            zero = self.d.make(pointer_type, SymbolicOp.CONSTANT, origin=origin, value=0)
            value = self.d.operation(SymbolicOp.SUB, ValueType.bv(pointer_type.bits), (value, zero), origin)
        low = index*8 if location.endian == Endian.LITTLE else location.width_bits-(index+1)*8
        if self.d.nodes[value].type.bits == 8: return value
        return self.d.operation(SymbolicOp.EXTRACT, ValueType.bv(8), (value,), origin, (low+7, low))
