"""Demand substitutions for legacy register/load definitions on CIR.

Rule references: AccurateDataFlow._update_register, _find_wrtmp_load_def_v1,
FastDataFlow.process_block_in_backward, FastSearch._summary_variable_in_loop.
Candidate collection is a separate operation over the loader snapshot; it does
not prove that writable memory still has its initial contents at runtime.
"""
from collections import deque
from dataclasses import dataclass
from itertools import product
from emtaint.core import BlockId, Completeness
from emtaint.core.contracts import Constant, ValueType
from emtaint.ir.canonical import (Compute, ReadRegister, WriteRegister, LoadEffect,
    CallEffect, DirectTarget, BranchEffect, JumpEffect, UnknownEffect, StoreEffect)
from emtaint.memory import SymbolicOp, AliasKind
from emtaint.memory.access_path import Offset, Deref, Index
from emtaint.memory.access_graph import AccessGraphArena


@dataclass(frozen=True)
class DemandBudget:
    steps:int=100000
    alternatives:int=256
    depth:int=160


class DemandLimit(RuntimeError):
    def __init__(self, message, *, dimension=None):
        super().__init__(message)
        self.dimension=dimension

@dataclass(frozen=True)
class ArgumentRead:
    width_bits:int
    endian:object
    origin:str


class LegacyDemand:
    def __init__(self, function, port, cfg, initial, *, budget=DemandBudget(), summaries=None):
        self.function, self.port, self.initial, self.budget=function, port, initial, budget
        self.blocks={b.id:b for b in function.blocks}
        self.steps=0
        self.notes=[]
        self.rules=set()
        self.summaries=dict(summaries or {})
        self.loads={}
        self.memo={}
        self.active={}
        self.cycles=set()
        self.apg=port.apg
        self.increment_cache={}
        self.predecessors={b:set() for b in self.blocks}
        for edge in cfg.edges:
            if edge.source in self.blocks and edge.target in self.blocks:self.predecessors[edge.target].add(edge.source)
        self.defs={e.result.id:(b.id, i, e) for b in function.blocks for i, e in enumerate(b.effects)
                   if isinstance(e, (Compute, ReadRegister, LoadEffect))}
        for b in function.blocks:
            for i, e in enumerate(b.effects):
                if isinstance(e, CallEffect):
                    for result in e.results:self.defs[result.id]=(b.id, i, e)
        self.stack_proven=all(self.sp_relative(e.value) for b in function.blocks for e in b.effects
            if isinstance(e, WriteRegister) and e.target.register=='sp')
        self.stack_proven &= not any(
            ('sp' in e.footprint.clobbered_registers or '*' in e.footprint.clobbered_registers)
            if isinstance(e, CallEffect) else ('sp' in e.may_write_registers or '*' in e.may_write_registers)
            for b in function.blocks for e in b.effects if isinstance(e, (CallEffect, UnknownEffect)))
        if self.stack_proven:self.stack_proven=self.prove_stack_range(cfg)

    def prove_stack_range(self, cfg):
        """A frame label alone cannot prove disjointness after SP arithmetic.

        Propagate finite SP displacements through the source CFG, including
        balanced allocation/deallocation loops. Escaping/wrapping addresses or
        an unbounded displacement frontier disable the frame fast path.
        """
        transfers={}
        bits=self.port.engine.architecture.pointer_bits
        mod=1<<bits
        signed=lambda value:(value+mod//2)%mod-mod//2
        for block in self.function.blocks:
            current={0}
            values={}
            accesses=[]
            intermediate={0}
            def offset(operand):return values.get(operand.id) if hasattr(operand, 'id') else None
            for effect in block.effects:
                if isinstance(effect, ReadRegister) and effect.source.register=='sp':values[effect.result.id]=set(current)
                elif isinstance(effect, Compute):
                    result=None
                    if effect.op.value=='copy':result=offset(effect.args[0])
                    elif effect.op.value in ('add', 'sub'):
                        base=offset(effect.args[0])
                        constant=self.literal(effect.args[1])
                        if base is not None and constant is not None:
                            delta=signed(constant)*(1 if effect.op.value=='add' else -1)
                            result={x+delta for x in base}
                        elif effect.op.value=='add' and self.literal(effect.args[0])==0:result=offset(effect.args[1])
                    elif effect.op.value=='if':
                        a, b=offset(effect.args[1]), offset(effect.args[2])
                        if a is not None and b is not None:result=a|b
                    if result is not None:values[effect.result.id]=set(result)
                elif isinstance(effect, WriteRegister) and effect.target.register=='sp':
                    if getattr(effect.guard, 'value', None) is False:continue
                    update=offset(effect.value)
                    if update is None:return False
                    current=set(update) if getattr(effect.guard, 'value', None) is True else current|update
                    intermediate|=current
                if isinstance(effect, (LoadEffect, StoreEffect)):
                    address=offset(effect.address)
                    if address is not None:accesses.extend((x, effect.width_bits//8) for x in address)
            transfers[block.id]=(tuple(current), tuple((x, 1) for x in intermediate)+tuple(accesses))
        todo=deque(((self.function.entry, 0),))
        seen=set()
        per_block={}
        base=0x7fffffff
        segments=getattr(self.port.engine, 'segments', ())
        while todo:
            block, delta=todo.popleft()
            if (block, delta) in seen:continue
            seen.add((block, delta))
            per_block.setdefault(block, set()).add(delta)
            if len(seen)>100000 or len(per_block[block])>64:return False
            exits, accesses=transfers[block]
            for relative, width in accesses:
                absolute=base+delta+relative
                if absolute<0 or absolute+width>mod:return False
                if any(absolute<start+size and start<absolute+width for start, data, size, flags in segments):return False
            for target in cfg.successors(block):
                todo.extend((target, delta+step) for step in exits)
        return True

    def tick(self, depth):
        self.port.validate_current()
        self.steps+=1
        if self.steps>self.budget.steps or depth>self.budget.depth:
            raise DemandLimit('Backward demand step/depth limit; unresolved frontier remains',
                dimension='steps' if self.steps>self.budget.steps else 'depth')

    def union(self, items):
        result=tuple(dict.fromkeys(x for part in items for x in part))
        if len(result)>self.budget.alternatives:raise DemandLimit('Backward alternative budget; no empty-set conclusion', dimension='alternatives')
        return result

    def contains(self, reference, leaves):
        seen=set()
        pending=[reference]
        d=self.port.engine.dag
        while pending:
            x=pending.pop()
            if x in leaves:return True
            if x in seen:continue
            seen.add(x)
            pending.extend(d.nodes[x].operands)
            if x in self.loads:pending.append(self.loads[x][0])
        return False

    def guard_concrete(self, reference):return self.port.concrete(reference)

    def operation(self, effect, depth):
        if effect.op.value=='if':
            guards=self.value(effect.args[0], depth+1)
            choices={self.guard_concrete(g) for g in guards}
            branches=[]
            if choices!={False}:branches.append(self.value(effect.args[1], depth+1))
            if choices!={True}:branches.append(self.value(effect.args[2], depth+1))
            if None in choices:self.notes.append('Conditional value alternatives retain unresolved feasibility')
            return self.union(branches)
        groups=[self.value(a, depth+1) for a in effect.args]
        amount=1
        for g in groups:amount*=len(g)
        if amount>self.budget.alternatives:raise DemandLimit('Backward expression product budget', dimension='alternatives')
        return self.union((self.port.operation(effect.op, effect.result.type, args, effect.origin, effect.params),)
                          for args in product(*groups))

    def value(self, operand, depth=0):
        self.tick(depth)
        p=self.port
        origin=p.engine.origins[0].id
        if isinstance(operand, Constant):return (p.constant(operand.value, operand.type, origin),)
        key=('value', operand.id)
        if key in self.memo:return self.memo[key]
        if operand.id not in self.defs:return (p.unknown(operand.type, origin, 'Undefined demand value '+operand.id),)
        block, index, effect=self.defs[operand.id]
        origin=effect.origin
        if isinstance(effect, Compute):
            self.rules.add('legacy._update_register/scalar-substitution')
            result=self.operation(effect, depth)
        elif isinstance(effect, ReadRegister):
            source=effect.source
            result=self.register(block, index, source.register, source.register_width_bits, depth+1)
            if source.bit_offset or source.width_bits!=source.register_width_bits:
                result=tuple(p.operation(SymbolicOp.EXTRACT, operand.type, (x,), origin,
                    (source.bit_offset+source.width_bits-1, source.bit_offset)) for x in result)
        elif isinstance(effect, LoadEffect):
            self.rules.add('legacy._find_wrtmp_load_def_v1')
            result=self.union(self.read(block, index, address, effect, depth+1)
                              for address in self.value(effect.address, depth+1))
        elif isinstance(effect, CallEffect):
            self.rules.add('legacy._update_expr_from_callees/return')
            summary=self.summaries.get(effect.target.function) if isinstance(effect.target, DirectTarget) else None
            result=(summary.instantiate(self, effect, depth+1) if hasattr(summary, 'instantiate') else summary(self, effect, depth+1)) if summary else (p.unknown(operand.type, origin, 'Unresolved callee return alias'),)
        else:raise TypeError(type(effect))
        if not any(self.contains(x, self.cycles) for x in result):self.memo[key]=result
        return result

    def register(self, block, index, name, width, depth):
        self.tick(depth)
        p=self.port
        origin=self.blocks[block].effects[0].origin
        # Several reads after the same definition denote one demand. Keying
        # by every read/cutoff creates false nested induction variables.
        index=self.definition_cutoff(block, index, name)
        key=('reg', block, index, name)
        if key in self.memo:return self.memo[key]
        if key in self.active:return (self.active[key],)
        placeholder=p.symbol('legacy-cycle:'+str(len(self.cycles)), ValueType.bv(width), origin)
        self.active[key]=placeholder
        self.cycles.add(placeholder)
        try:
            summarized=self.induction(block, index, name, width, depth+1)
            if summarized is not None:
                if not any(self.contains(x, self.cycles) for x in summarized):self.memo[key]=summarized
                return summarized
            result=None
            for position in range(index-1, -1, -1):
                effect=self.blocks[block].effects[position]
                if isinstance(effect, WriteRegister) and effect.target.register==name:
                    if effect.target.width_bits!=width or effect.target.bit_offset:
                        result=(p.unknown(ValueType.bv(width), effect.origin, 'Partial backward register definition'),)
                        break
                    result=self.value(effect.value, depth+1)
                    if getattr(effect.guard, 'value', None) is not True:
                        guards=self.value(effect.guard, depth+1)
                        concrete={self.guard_concrete(g) for g in guards}
                        if concrete=={False}:
                            result=None
                            continue
                        if concrete!={True}:
                            result=self.union((result, self.register(block, position, name, width, depth+1)))
                    break
                if isinstance(effect, CallEffect) and (name in effect.footprint.clobbered_registers or '*' in effect.footprint.clobbered_registers):
                    result=(p.unknown(ValueType.bv(width), effect.origin, 'Call clobber '+name),)
                    break
                if isinstance(effect, UnknownEffect) and (name in effect.may_write_registers or '*' in effect.may_write_registers):
                    result=(p.unknown(ValueType.bv(width), effect.origin, 'Unsupported register definition '+name),)
                    break
            if result is None:
                inputs=[]
                entry=False
                todo=deque(self.predecessors[block])
                seen=set()
                if block==self.function.entry:entry=True
                while todo:
                    predecessor=todo.popleft()
                    self.tick(depth)
                    if predecessor in seen:continue
                    seen.add(predecessor)
                    cutoff=self.definition_cutoff(predecessor, len(self.blocks[predecessor].effects), name)
                    if cutoff:
                        inputs.append(self.register(predecessor, cutoff, name, width, depth+1))
                    else:
                        if predecessor==self.function.entry or not self.predecessors[predecessor]:entry=True
                        todo.extend(self.predecessors[predecessor])
                if entry or not inputs:
                    entry=dict(self.initial.registers).get(name)
                    inputs.append((entry or p.symbol('entry:'+name, ValueType.bv(width), origin),))
                result=self.union(inputs)
            base=[x for x in result if not self.contains(x, {placeholder})]
            recurrent=[x for x in result if self.contains(x, {placeholder})]
            if recurrent and base:
                strides=[self.affine(x, placeholder) for x in recurrent]
                if all(s is not None and s[0]==1 for s in strides):
                    expanded=list(base)
                    for coefficient, stride in strides:
                        if stride==0:continue
                        self.rules.add('legacy._summary_variable_in_loop/base+offset*i')
                        i=p.symbol('i', ValueType.bv(width), origin)
                        delta=p.operation(SymbolicOp.MUL, ValueType.bv(width), (i, p.constant(stride%(1<<width), ValueType.bv(width), origin)), origin)
                        expanded.extend(p.operation(SymbolicOp.ADD, ValueType.bv(width), (b, delta), origin) for b in base)
                    result=tuple(dict.fromkeys(expanded))
                else:self.notes.append('Non-affine recurrence retained as unknown remainder: '+name)
            if not any(self.contains(x, self.cycles) for x in result):self.memo[key]=result
            return result
        finally:self.active.pop(key, None)

    def definition_cutoff(self, block, index, name):
        for position in range(index-1, -1, -1):
            effect=self.blocks[block].effects[position]
            if isinstance(effect, WriteRegister) and effect.target.register==name:return position+1
            if isinstance(effect, CallEffect) and (name in effect.footprint.clobbered_registers or '*' in effect.footprint.clobbered_registers):return position+1
            if isinstance(effect, UnknownEffect) and (name in effect.may_write_registers or '*' in effect.may_write_registers):return position+1
        return 0

    def reaching(self, block, index, name):
        todo=deque(((block, index),))
        seen=set()
        definitions=set()
        entry=False
        while todo:
            current, cutoff=todo.popleft()
            if (current, cutoff) in seen:continue
            seen.add((current, cutoff))
            self.tick(0)
            defined=self.definition_cutoff(current, cutoff, name)
            if defined:
                definitions.add((current, defined))
                continue
            if current==self.function.entry or not self.predecessors[current]:entry=True
            todo.extend((p, len(self.blocks[p].effects)) for p in self.predecessors[current])
        return definitions, entry

    def linear_register(self, operand, name, seen=frozenset()):
        if isinstance(operand, Constant):return (0, operand.value, ())
        if operand.id in seen or operand.id not in self.defs:return None
        block, index, effect=self.defs[operand.id]
        seen=seen|{operand.id}
        if isinstance(effect, ReadRegister):
            return (1, 0, ((block, index),)) if effect.source.register==name else None
        if not isinstance(effect, Compute):return None
        if effect.op.value=='copy':return self.linear_register(effect.args[0], name, seen)
        if effect.op.value not in ('add', 'sub'):return None
        a, b=(self.linear_register(x, name, seen) for x in effect.args)
        if a is None or b is None:return None
        sign=1 if effect.op.value=='add' else -1
        return a[0]+sign*b[0], a[1]+sign*b[1], a[2]+b[2]

    def increments(self, name, width):
        if name in self.increment_cache:return self.increment_cache[name]
        result={}
        for block in self.function.blocks:
            for index, effect in enumerate(block.effects):
                if not isinstance(effect, WriteRegister) or effect.target.register!=name or getattr(effect.guard, 'value', None) is not True:continue
                affine=self.linear_register(effect.value, name)
                if affine is None or affine[0]!=1 or len(affine[2])!=1:continue
                stride=affine[1]%(1<<width)
                if not stride:continue
                point=affine[2][0]
                definitions, _=self.reaching(point[0], point[1], name)
                if (block.id, index+1) in definitions:result[block.id, index+1]=(stride, point)
        self.increment_cache[name]=result
        return result

    def induction(self, block, index, name, width, depth):
        """Old DDG inc_flag + base/offset*i, before expanding cyclic uses.

        The increment must be a real reaching-definition cycle, not merely an
        add instruction inside a CFG loop. Multiple strides remain explicit.
        """
        increments=self.increments(name, width)
        if not increments:return None
        definitions, entry=self.reaching(block, index, name)
        todo=list(definitions)
        seen=set()
        bases=set()
        strides=set()
        while todo:
            definition=todo.pop()
            if definition in seen:continue
            seen.add(definition)
            if definition in increments:
                stride, point=increments[definition]
                strides.add(stride)
                incoming, at_entry=self.reaching(point[0], point[1], name)
                entry|=at_entry
                todo.extend(incoming)
            else:bases.add(definition)
        if len(strides)!=1 or not (bases or entry):return None
        origin=self.blocks[block].effects[0].origin
        p=self.port
        t=ValueType.bv(width)
        values=[]
        for source, cutoff in sorted(bases, key=lambda x:(x[0].token, x[1])):
            values.extend(self.register(source, cutoff, name, width, depth+1))
        if entry:values.append(dict(self.initial.registers).get(name) or p.symbol('entry:'+name, t, origin))
        stride=next(iter(strides))
        i=p.symbol('i', t, origin)
        delta=p.operation(SymbolicOp.MUL, t, (i, p.constant(stride, t, origin)), origin)
        expanded=tuple(p.operation(SymbolicOp.ADD, t, (base, delta), origin) for base in values)
        self.rules.add('legacy.label_inc_flag_in_loop/DDG + _summary_variable_in_loop')
        return self.union((values, expanded))

    def affine(self, ref, variable):
        if ref==variable:return (1, 0)
        d=self.port.engine.dag
        n=d.nodes[ref]
        constant=self.port.concrete(ref)
        if type(constant) is int:return (0, constant)
        if n.op==SymbolicOp.COPY:return self.affine(n.operands[0], variable)
        if n.op not in (SymbolicOp.ADD, SymbolicOp.SUB, SymbolicOp.MUL):return None
        a, b=(self.affine(x, variable) for x in n.operands)
        if a is None or b is None:return None
        if n.op==SymbolicOp.ADD:return a[0]+b[0], a[1]+b[1]
        if n.op==SymbolicOp.SUB:return a[0]-b[0], a[1]-b[1]
        if a[0] and b[0]:return None
        return a[0]*b[1]+b[0]*a[1], a[1]*b[1]

    def read(self, block, index, address, effect, depth):
        p=self.port
        e=p.engine
        origin=effect.origin
        absolute=p.concrete(address)
        binding=self.address_binding(address)
        loc=e.location(*binding, effect.width_bits, effect.endian, origin) if binding else e.location(None, None, effect.width_bits, effect.endian, origin)
        loc=p.addressed_location(loc, address)
        # MemoryRead is a versioned leaf. Its address demand is separate data,
        # never an unsolvable custom Load embedded in the symbolic expression.
        ref=p.read(self.initial.memory, loc, p.constant(True, ValueType.boolean(), origin), origin).value
        self.loads[ref]=(address, effect.width_bits, effect.endian, origin)
        if binding and binding[1] is not None:
            root, offset=binding
            path=e.path(root, (Offset(offset), Deref(e.architecture.pointer_bits, effect.width_bits, effect.endian)), effect.width_bits, effect.endian, origin)
            graph=self.apg.intern(path, p.point(origin))
            e.graphs[graph.id]=graph
        else:
            # Keep the old bounded table-index language in APG separately
            # from the unresolved runtime location (which remains unknown).
            for variable, node in tuple(e.dag.nodes.items()):
                if node.op!=SymbolicOp.SYMBOL or node.value!='i':continue
                affine=self.affine(address, variable)
                if affine is None or affine[0]<=0:continue
                stride, base=affine
                root_offset=e.address(base%(1<<e.architecture.pointer_bits)) if hasattr(e, 'address') else None
                if root_offset:
                    root, offset=root_offset
                    path=e.path(root, (Offset(offset), Index(variable, stride, 0, 0xfff),
                        Deref(e.architecture.pointer_bits, effect.width_bits, effect.endian)), effect.width_bits, effect.endian, origin)
                    graph=self.apg.intern(path, p.point(origin))
                    e.graphs[graph.id]=graph
                break
        definitions, killed=self.memory_definitions(block, index, loc, effect, set(), depth+1)
        initial=ref
        frames=getattr(e, 'entry_frame_inputs', {})
        if loc.object_id in frames and loc.offset_lower==loc.offset_upper and loc.offset_lower is not None and effect.width_bits==e.architecture.pointer_bits:
            word=e.architecture.pointer_bits//8
            offset=loc.offset_lower
            if offset>=0 and offset%word==0 and offset//word<len(frames[loc.object_id]):
                initial=frames[loc.object_id][offset//word]
                self.rules.add('legacy.judge_stack_argument/aligned-entry-slot')
        return self.union((definitions, () if killed else (initial,)))

    def memory_definitions(self, block, index, loc, load, seen, depth):
        p=self.port
        e=p.engine
        alternatives=[]
        todo=deque(((block, index),))
        visited=set()
        initial_possible=False
        # A use/def worklist visits each predecessor demand once. Enumerating
        # every CFG path repeats joins exponentially and is not needed to find
        # reaching definitions. A repeated/cyclic demand keeps the old read.
        while todo:
            current, cutoff=todo.popleft()
            self.tick(depth)
            if (current, cutoff) in visited:
                initial_possible=True
                continue
            visited.add((current, cutoff))
            killed=False
            for position in range(cutoff-1, -1, -1):
                effect=self.blocks[current].effects[position]
                if isinstance(effect, CallEffect):
                    self.notes.append('Legacy loader candidate crosses call; runtime memory has unknown remainder')
                    summary=self.summaries.get(effect.target.function) if isinstance(effect.target, DirectTarget) else None
                    if summary and getattr(summary, 'stores', ()):
                        values, defined=self.callee_definitions(summary, effect, loc, load, depth+1)
                        alternatives.extend(values)
                        if defined:
                            killed=True
                            break
                if not isinstance(effect, StoreEffect) or getattr(effect.guard, 'value', None) is False:continue
                # The old action rule compares addr_value/dst_alias first. Do
                # not recursively demand every unrelated store-address slice.
                # An unproved address is a MayAlias alternative, not NoAlias.
                binding=self.local_address(effect.address)
                bindings=(binding,)
                if binding and binding[0].region=='stack' and binding[1] is None and loc.object_id is not None and e.roots[loc.object_id].region=='stack':
                    precise=[]
                    for address in self.value(effect.address, depth+1):
                        absolute=p.concrete(address)
                        if type(absolute) is int:
                            precise.append((binding[0], (absolute-0x7fffffff)%(1<<e.architecture.pointer_bits)))
                        else:precise.append(binding)
                    bindings=tuple(precise)
                for binding in bindings:
                    store=e.location(*binding, effect.width_bits, effect.endian, effect.origin) if binding else e.location(None, None, effect.width_bits, effect.endian, effect.origin)
                    alias=p.alias(self.initial.memory, store, loc)
                    if alias.kind==AliasKind.NO:continue
                    if alias.kind==AliasKind.MUST and store.width_bits==loc.width_bits and getattr(effect.guard, 'value', None) is True:
                        self.rules.add('legacy._do_store_define/MustAlias')
                        for value in self.value(effect.value, depth+1):
                            written=p.write(self.initial.memory, store, value, p.constant(True, ValueType.boolean(), effect.origin), effect.origin)
                            read=p.read(written.state, loc, p.constant(True, ValueType.boolean(), load.origin), load.origin)
                            p.read_definition(read.value, p.constant(True, ValueType.boolean(), load.origin), load.origin)
                            # Exact old _do_store_define substitutes the stored
                            # value. Keep its shared address dependencies instead
                            # of hiding them behind an extra deferred-read leaf.
                            alternatives.append(value if store.endian==loc.endian else read.value)
                        killed=True
                        break
                    self.rules.add('legacy._do_store_define/MayAlias')
                    alternatives.append(p.unknown(ValueType.bv(loc.width_bits), load.origin, 'MayAlias/partial/guarded reaching store'))
                if killed:break
            if not killed:
                if current==self.function.entry or not self.predecessors[current]:initial_possible=True
                todo.extend((predecessor, len(self.blocks[predecessor].effects)) for predecessor in self.predecessors[current])
        return self.union((alternatives,)), not initial_possible

    def local_address(self, operand, seen=frozenset()):
        e=self.port.engine
        if isinstance(operand, Constant):
            return self.address_binding(self.port.constant(operand.value, operand.type, e.origins[0].id))
        if operand.id in seen or operand.id not in self.defs:return None
        seen=seen|{operand.id}
        block, index, effect=self.defs[operand.id]
        if isinstance(effect, ReadRegister):
            name=effect.source.register
            if name=='sp' and self.stack_proven:
                # SP's object identity is the explicit legacy entry-frame
                # convention. Unknown offset forbids a must-alias conclusion.
                stack=dict(self.initial.addresses).get('reg:sp')
                return (stack[0], None) if stack else None
            for prior in reversed(self.blocks[block].effects[:index]):
                if isinstance(prior, WriteRegister) and prior.target.register==name:
                    return self.local_address(prior.value, seen)
                if isinstance(prior, CallEffect) and (name in prior.footprint.clobbered_registers or '*' in prior.footprint.clobbered_registers):return None
            initial=dict(self.initial.addresses).get('reg:'+name)
            return initial if initial is not None and initial[0].region=='argument' else None
        if isinstance(effect, Compute):
            if effect.op.value=='copy':return self.local_address(effect.args[0], seen)
            if effect.op.value=='add' and isinstance(effect.args[0], Constant) and effect.args[0].value==0:
                return self.local_address(effect.args[1], seen)
            if effect.op.value in ('add', 'sub') and isinstance(effect.args[1], Constant):
                binding=self.local_address(effect.args[0], seen)
                if binding:
                    root, offset=binding
                    delta=effect.args[1].value
                    return root, None if offset is None else (offset+(delta if effect.op.value=='add' else -delta))%(1<<e.architecture.pointer_bits)
        return None

    def literal(self, operand, seen=frozenset()):
        if isinstance(operand, Constant):return operand.value
        if operand.id in seen or operand.id not in self.defs:return None
        effect=self.defs[operand.id][2]
        if isinstance(effect, Compute) and effect.op.value=='copy':return self.literal(effect.args[0], seen|{operand.id})
        return None

    def sp_relative(self, operand, seen=frozenset()):
        if isinstance(operand, Constant) or operand.id in seen or operand.id not in self.defs:return False
        effect=self.defs[operand.id][2]
        seen=seen|{operand.id}
        if isinstance(effect, ReadRegister):return effect.source.register=='sp'
        if isinstance(effect, Compute):
            if effect.op.value=='copy':return self.sp_relative(effect.args[0], seen)
            if effect.op.value in ('add', 'sub'):
                if self.literal(effect.args[1]) is not None:return self.sp_relative(effect.args[0], seen)
                if effect.op.value=='add' and self.literal(effect.args[0])==0:return self.sp_relative(effect.args[1], seen)
        return False

    def address_binding(self, reference, seen=frozenset()):
        p=self.port
        e=p.engine
        if reference in seen:return None
        seen=seen|{reference}
        absolute=p.concrete(reference)
        if type(absolute) is int:
            binding=e.address(absolute) if hasattr(e, 'address') else None
            if binding:return binding
            if 0x7fefffff<=absolute<=0x8000ffff:
                stack=dict(self.initial.addresses).get('reg:sp')
                if stack:return stack[0], (absolute-0x7fffffff)%(1<<e.architecture.pointer_bits)
        n=e.dag.nodes[reference]
        if n.op==SymbolicOp.SYMBOL and n.value.startswith('argument:'):
            index=int(n.value.split(':')[1])
            registers=self.function.abi.argument_registers or ('r0', 'r1', 'r2', 'r3')
            root=getattr(e, 'argument_roots', {}).get(index)
            return (root, 0) if root else None
        if n.op==SymbolicOp.COPY:return self.address_binding(n.operands[0], seen)
        if n.op in (SymbolicOp.ADD, SymbolicOp.SUB):
            if n.op==SymbolicOp.ADD and p.concrete(n.operands[0])==0:return self.address_binding(n.operands[1], seen)
            base=self.address_binding(n.operands[0], seen)
            offset=p.concrete(n.operands[1])
            if base and type(offset) is int:
                if base[1] is None:
                    return base[0], None
                return base[0], (base[1]+(offset if n.op==SymbolicOp.ADD else -offset))%(1<<e.architecture.pointer_bits)
        return None

    def callee_definitions(self, summary, call, loc, load, depth):
        p=self.port
        e=p.engine
        values=[]
        killed=False
        def unknown_write():
            p.havoc(self.initial.memory, ('*',), 'Callee write has unresolved address correspondence', call.origin)
            self.notes.append('Unproved callee write correspondence retains unknown memory; no exact stored-value substitution')
            values.append(p.unknown(ValueType.bv(loc.width_bits), load.origin, 'Unproved callee memory definition'))
        if loc.object_id is None or loc.offset_lower is None or loc.offset_lower!=loc.offset_upper:
            unknown_write()
            return self.union((values,)), False
        # Original _update_exprs_with_alias/_do_store_define first select a
        # matching argument/address. Expanding every callee store value before
        # this match creates unrelated dependencies and expression explosion.
        for definition in reversed(summary.stores):
            candidates = tuple(summary.addresses(self, call, definition, depth))
            # A strong update must cover every possible target of this Store.
            # Finding one MustAlias target is insufficient when another path
            # writes elsewhere and leaves the old definition live.
            candidate_aliases = []
            for address in candidates:
                binding = self.address_binding(address)
                if binding is None:
                    candidate_aliases.append(None)
                    continue
                candidate_aliases.append(p.alias(
                    self.initial.memory,
                    e.location(*binding, definition.width_bits,
                               definition.endian, call.origin),
                    loc,
                ))
            all_correspondences_complete = bool(candidate_aliases) and all(
                result is not None
                and result.assessment.status == Completeness.COMPLETE
                and result.kind in (AliasKind.NO, AliasKind.MUST)
                for result in candidate_aliases
            )
            universal_must = all_correspondences_complete and all(
                result.kind == AliasKind.MUST for result in candidate_aliases
            )
            for address in candidates:
                binding=self.address_binding(address)
                store=e.location(*binding, definition.width_bits, definition.endian, call.origin) if binding else e.location(None, None, definition.width_bits, definition.endian, call.origin)
                alias=p.alias(self.initial.memory, store, loc)
                if alias.kind==AliasKind.NO:continue
                corresponding=(store.object_id==loc.object_id and store.offset_lower is not None and store.offset_lower==store.offset_upper)
                if not corresponding:
                    unknown_write()
                    continue
                for value, guard in summary.stored_values(self, call, definition, depth):
                    if p.concrete(guard) is False:continue
                    written=p.write(self.initial.memory, store, value, guard, call.origin)
                    read=p.read(written.state, loc, p.constant(True, ValueType.boolean(), load.origin), load.origin)
                    p.read_definition(read.value, p.constant(True, ValueType.boolean(), load.origin), load.origin)
                    full=store.width_bits==loc.width_bits and store.endian==loc.endian and store.offset_lower==loc.offset_lower
                    values.append(value if full else read.value)
                    self.rules.add('legacy._update_expr_from_callees/argument-def + _do_store_define')
                    if (
                            universal_must and alias.kind == AliasKind.MUST
                            and full and p.concrete(guard) is True
                            and definition.must_execute
                            and (not summary.unknown_effects
                                 or definition.no_unknown_after)):
                        killed=True
                        break
                    if not (
                            all_correspondences_complete
                            and alias.kind == AliasKind.MUST and full
                            and p.concrete(guard) is True):
                        values.append(p.unknown(
                            ValueType.bv(loc.width_bits), load.origin,
                            'Callee may-definition retains earlier/unknown memory'))
                if killed:break
            if killed:break
        return self.union((values,)), killed

    def stack_argument(self, call, slot, width, depth):
        block, index=next((b.id, i) for b in self.function.blocks for i, e in enumerate(b.effects) if e==call)
        p=self.port
        e=p.engine
        t=ValueType.bv(e.architecture.pointer_bits)
        query=ArgumentRead(width, e.architecture.endian, call.origin)
        result=[]
        for sp in self.register(block, index, self.function.abi.stack_pointer or 'sp', t.bits, depth+1):
            address=p.operation(SymbolicOp.ADD, t, (sp, p.constant(slot*(t.bits//8), t, call.origin)), call.origin)
            result.extend(self.read(block, index, address, query, depth+1))
        return self.union((result,))
