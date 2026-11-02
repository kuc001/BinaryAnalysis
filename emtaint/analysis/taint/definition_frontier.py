"""Reuse the P6/old store-selection worklist without caching stored values.

Selection uses the same alias, width, guard, ordering and initial-read rules
as LegacyDemand.memory_definitions. Value substitution still runs at the real
query, with its actual read address/origin and immutable MemoryVersion. Only
completed frontiers with context-independent addresses are reusable. Scoped
object facts participate in the key; cyclic address placeholders disable reuse.
"""
from collections import deque
from emtaint.ir.canonical import StoreEffect, CallEffect
from emtaint.core.contracts import ValueType
from emtaint.memory import AliasKind


class DefinitionFrontierCache:
    def __init__(self, owner, limit=8192):
        self.owner=owner
        self.limit=limit
        self.cache={}
        self.active=set()
        self.hits=0
        self.misses=0
        self.max_must_projection_effects=8192
        self.effect_count=sum(len(block.effects) for block in owner.function.blocks)
        self.unknown_ready=False
        self.before_stores={}
        self.before_calls={}
        self.local_stores={}
        self.local_calls={}
        self.before_unknown_stores={}
        self.local_unknown_stores={}
        self.global_must_stores=set()

    def prepare_unknown(self, depth):
        """Exact existential projection of the no-kill predecessor worklist.

        With an unknown queried object, P5 alias is always UNKNOWN, regardless
        of the other address. Every possible Store contributes the same
        Unknown value; no Store is a MustAlias kill. A finite predecessor walk
        without kills always retains the initial read (entry or a repetition).
        Thus only reachable Store/Call existence is needed, not path copies.
        """
        d=self.owner
        successors={block:[] for block in d.blocks}
        for block, predecessors in d.predecessors.items():
            for predecessor in predecessors:successors[predecessor].append(block)
        for block, body in d.blocks.items():
            self.local_stores[block]=next(((i, effect) for i, effect in enumerate(body.effects)
                if isinstance(effect, StoreEffect) and getattr(effect.guard, 'value', None) is not False), None)
            self.local_calls[block]=next((i for i, effect in enumerate(body.effects) if isinstance(effect, CallEffect)), None)
            self.local_unknown_stores[block]=None
            for i, effect in enumerate(body.effects):
                if not isinstance(effect, StoreEffect) or getattr(effect.guard, 'value', None) is False:continue
                binding=d.local_address(effect.address)
                if binding is None and self.local_unknown_stores[block] is None:self.local_unknown_stores[block]=(i, effect)
                if (binding and binding[0].region=='global' and binding[1] is not None
                        and getattr(effect.guard, 'value', None) is True):
                    self.global_must_stores.add((binding[0].object_id, binding[1], effect.width_bits))
        after_stores={block:None if item is None else item[1] for block, item in self.local_stores.items()}
        after_unknown={block:None if item is None else item[1] for block, item in self.local_unknown_stores.items()}
        after_calls={block:item is not None for block, item in self.local_calls.items()}
        todo=deque(d.blocks)
        queued=set(todo)
        while todo:
            block=todo.popleft()
            queued.remove(block)
            d.tick(depth)
            changed=False
            if after_stores[block] is None:
                incoming=next((after_stores[pre] for pre in d.predecessors[block] if after_stores[pre] is not None), None)
                if incoming is not None:
                    after_stores[block]=incoming
                    changed=True
            if not after_calls[block] and any(after_calls[pre] for pre in d.predecessors[block]):
                after_calls[block]=True
                changed=True
            if after_unknown[block] is None:
                incoming=next((after_unknown[pre] for pre in d.predecessors[block] if after_unknown[pre] is not None), None)
                if incoming is not None:
                    after_unknown[block]=incoming
                    changed=True
            if changed:
                for successor in successors[block]:
                    if successor not in queued:
                        todo.append(successor)
                        queued.add(successor)
        self.before_stores={block:next((after_stores[pre] for pre in d.predecessors[block]
            if after_stores[pre] is not None), None) for block in d.blocks}
        self.before_calls={block:any(after_calls[pre] for pre in d.predecessors[block]) for block in d.blocks}
        self.before_unknown_stores={block:next((after_unknown[pre] for pre in d.predecessors[block]
            if after_unknown[pre] is not None), None) for block in d.blocks}
        self.unknown_ready=True

    def unknown_query(self, block, index, location, load, depth):
        d=self.owner
        p=d.port
        e=p.engine
        if not self.unknown_ready:self.prepare_unknown(depth)
        if location.object_id is None:
            local=self.local_stores[block]
            witness=local[1] if local is not None and local[0]<index else self.before_stores[block]
        else:
            # For a global query, the original local-address selector never
            # expands stack stores into global addresses. A MustAlias kill
            # therefore needs an explicit same-root/offset/width store. If no
            # such store exists anywhere in this immutable body, a reachable
            # unresolved-pointer store is sufficient for the same Unknown
            # alternative; every predecessor path retains the initial read.
            if (location.object_id, location.offset_lower, location.width_bits) in self.global_must_stores:return None
            local=self.local_unknown_stores[block]
            witness=local[1] if local is not None and local[0]<index else self.before_unknown_stores[block]
            if witness is None:return None
        d.tick(depth)
        local_call=self.local_calls[block]
        if (local_call is not None and local_call<index) or self.before_calls[block]:
            d.notes.append('Legacy loader candidate crosses call; runtime memory has unknown remainder')
        if witness is None:return (), False
        binding=d.local_address(witness.address)
        store=(e.location(*binding, witness.width_bits, witness.endian, witness.origin) if binding else
            e.location(None, None, witness.width_bits, witness.endian, witness.origin))
        # Keep the real MemoryQueryPort as the alias authority. If its contract
        # changes, fall back to the original general worklist below.
        if p.alias(d.initial.memory, store, location).kind!=AliasKind.UNKNOWN:return None
        d.rules.add('legacy._do_store_define/MayAlias')
        return (p.unknown(ValueType.bv(location.width_bits), load.origin, 'MayAlias/partial/guarded reaching store'),), False

    def query(self, block, index, location, load, seen, depth):
        d=self.owner
        p=d.port
        e=p.engine
        if (location.object_id is None or
                (e.roots[location.object_id].region=='global' and location.byte_interval is not None)):
            result=self.unknown_query(block, index, location, load, depth)
            if result is not None:return result
        key=(block, index, location.id.scope, location.object_id, location.offset_lower, location.offset_upper,
            location.width_bits, location.endian, location.address_space, location.assessment,
            d.initial.memory, tuple(e.object_facts.items()))
        if key in self.active:
            # Preserve the original depth/frontier behavior for recursive
            # address definitions; never cache a context-dependent partial walk.
            from emtaint.analysis.dataflow.legacy_demand import LegacyDemand
            return LegacyDemand.memory_definitions(d, block, index, location, load, seen, depth)
        if d.cache_queries and key in self.cache:
            d.tick(depth)
            self.hits+=1
            stores, initial_possible=self.cache[key]
        else:
            self.misses+=1
            self.active.add(key)
            try:stores, initial_possible, cacheable=self.select(block, index, location, depth)
            finally:self.active.remove(key)
            if d.cache_queries and cacheable and len(self.cache)<self.limit:self.cache[key]=(stores, initial_possible)
        alternatives=[]
        for effect, store, alias in stores:
            if alias==AliasKind.MUST:
                d.rules.add('legacy._do_store_define/MustAlias')
                for value in d.value(effect.value, depth+1):
                    written=p.write(d.initial.memory, store, value, p.constant(True, ValueType.boolean(), effect.origin), effect.origin)
                    read=p.read(written.state, location, p.constant(True, ValueType.boolean(), load.origin), load.origin)
                    p.read_definition(read.value, p.constant(True, ValueType.boolean(), load.origin), load.origin)
                    alternatives.append(value if store.endian==location.endian else read.value)
            else:
                d.rules.add('legacy._do_store_define/MayAlias')
                alternatives.append(p.unknown(ValueType.bv(location.width_bits), load.origin, 'MayAlias/partial/guarded reaching store'))
        return d.union((alternatives,)), not initial_possible

    def select(self, block, index, location, depth):
        d=self.owner
        p=d.port
        e=p.engine
        stores=[]
        todo=deque(((block, index),))
        visited=set()
        initial_possible=False
        cacheable=True
        while todo:
            current, cutoff=todo.popleft()
            d.tick(depth)
            if (current, cutoff) in visited:
                initial_possible=True
                continue
            visited.add((current, cutoff))
            killed=False
            for position in range(cutoff-1, -1, -1):
                effect=d.blocks[current].effects[position]
                if isinstance(effect, CallEffect):
                    d.notes.append('Legacy loader candidate crosses call; runtime memory has unknown remainder')
                if not isinstance(effect, StoreEffect) or getattr(effect.guard, 'value', None) is False:continue
                binding=d.local_address(effect.address)
                if (location.object_id is not None and e.roots[location.object_id].region=='stack'
                        and (binding is None or (binding[0].region=='stack' and binding[1] is None))):
                    exact=d.exact_stack_address(effect.address)
                    if (exact is not None and exact[1] is not None
                            and exact[0].object_id==location.object_id):
                        projected=e.location(*exact, effect.width_bits, effect.endian, effect.origin)
                        projected_alias=p.alias(d.initial.memory, projected, location).kind
                        if (projected_alias==AliasKind.NO or
                                (projected_alias==AliasKind.MUST
                                 and self.effect_count<=self.max_must_projection_effects)):
                            binding=exact
                bindings=(binding,)
                if (binding and binding[0].region=='stack' and binding[1] is None and
                        location.object_id is not None and e.roots[location.object_id].region=='stack'):
                    precise=[]
                    for address in d.value(effect.address, depth+1):
                        if d.contains(address, d.cycles):cacheable=False
                        absolute=p.concrete(address)
                        precise.append((binding[0], (absolute-0x7fffffff)%(1<<e.architecture.pointer_bits))
                            if type(absolute) is int else binding)
                    bindings=tuple(precise)
                for binding in bindings:
                    store=(e.location(*binding, effect.width_bits, effect.endian, effect.origin) if binding else
                        e.location(None, None, effect.width_bits, effect.endian, effect.origin))
                    alias=p.alias(d.initial.memory, store, location)
                    if alias.kind==AliasKind.NO:continue
                    must=(alias.kind==AliasKind.MUST and store.width_bits==location.width_bits
                        and getattr(effect.guard, 'value', None) is True)
                    stores.append((effect, store, AliasKind.MUST if must else AliasKind.MAY))
                    if must:
                        killed=True
                        break
                if killed:break
            if not killed:
                if current==d.function.entry or not d.predecessors[current]:initial_possible=True
                todo.extend((predecessor, len(d.blocks[predecessor].effects)) for predecessor in d.predecessors[current])
        return tuple(stores), initial_possible, cacheable
