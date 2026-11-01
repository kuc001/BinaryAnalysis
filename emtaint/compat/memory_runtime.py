"""P6 pure descriptor adapter over P5 MemoryQueryPort; no native objects.

Core transfers use this public value/location/query interface, not heap internals.
"""
from itertools import product
from dataclasses import replace
from emtaint.core.contracts import MemoryLocationId,same_scope
from emtaint.memory.engine import token
from emtaint.core.contracts import ValueType,TypeKind,SymbolicExprId
from emtaint.memory import (SymbolicOp,ReadMemory,WriteMemory,UpdateKind,AliasKind)
from emtaint.memory.query_port import QueryBudget
from emtaint.memory.policies import BudgetExceeded
from emtaint.memory.access_graph import AccessGraphArena


class MemoryRuntimePort:
    def __init__(self,engine,budget=QueryBudget(),*,cache_alias_queries=False):
        self.engine=engine;self.scope=engine.scope;self.budget=budget
        self.initial=engine.initial;self.seed_addresses={}
        self.calls={name:0 for name in ('read','write','resolve_alias','resolve_definition','havoc')}
        self.validate_current=lambda:None
        self._concrete_memo={}
        self._alias_cache_enabled=cache_alias_queries;self._alias_cache={};self._alias_hits=0;self._alias_misses=0
        if not hasattr(engine,'access_graph_arena'):
            engine.access_graph_arena=AccessGraphArena(engine.scope,engine.budgets,graphs=engine.graphs)
        self.apg=engine.access_graph_arena

    def bind_address(self,name,root,offset):self.seed_addresses[name]=(root,offset)

    def constant(self,value,type_,origin):
        self.validate_current()
        return self.engine.dag.make(type_,SymbolicOp.CONSTANT,origin=origin,value=value)

    def symbol(self,name,type_,origin):
        self.validate_current();return self.engine.dag.symbol(name,type_,origin)

    def unknown(self,type_,origin,reason):
        self.validate_current()
        return self.engine.dag.make(type_,SymbolicOp.UNKNOWN,origin=origin,value=reason)

    def operation(self,op,type_,args,origin,params=()):
        self.validate_current()
        return self.engine.dag.operation(SymbolicOp(op.value if hasattr(op,'value') else op),type_,args,origin,params)

    def type_of(self,ref):return self.engine.dag.nodes[ref].type

    def concrete(self,ref):
        self.validate_current()
        literal=self.engine.dag.constant_value(ref)
        if literal is not None:return literal
        node=self.engine.dag.nodes[ref]
        if node.op in (SymbolicOp.SYMBOL,SymbolicOp.UNKNOWN):return None
        if ref in self._concrete_memo:return self._concrete_memo[ref]
        value=self.engine.constant_value(ref)
        # Only proven constants are cached. An unresolved read may later be
        # refined by new object/alias evidence; every read ID includes its
        # immutable memory version, and a stale port still fails above.
        if value is not None:self._concrete_memo[ref]=value
        return value

    def guard_concrete(self,ref):
        self.validate_current()
        literal=self.engine.dag.constant_value(ref)
        if literal is not None:return literal
        evaluate=getattr(self.engine,'runtime_constant_value',self.engine.constant_value)
        return evaluate(ref)

    def point(self,origin):
        return self.engine.origin_record(origin).point

    def location(self,operand,bindings,values,width,endian,origin):
        self.validate_current()
        binding=bindings.get(operand.id) if hasattr(operand,'id') else None
        if binding is None:
            value=operand.value if hasattr(operand,'value') else self.concrete(values[operand.id]) if operand.id in values else None
            if type(value) is int and hasattr(self.engine,'address'):binding=self.engine.address(value)
        if binding is None:
            loc=self.engine.location(None,None,width,endian,origin)
            return self.addressed_location(loc,values.get(operand.id,operand) if hasattr(operand,'id') else operand)
        root,offset=binding
        return self.engine.location(root,offset%(1<<self.engine.architecture.pointer_bits),width,endian,origin)

    def addressed_location(self,location,address):
        """Keep unknown read identities separate without asserting NoAlias.

        Two different address demands at the same native origin can share an
        unknown location descriptor. They cannot share one deferred-read leaf:
        that would collapse nested loads and lose the address dependency.
        """
        self.validate_current()
        loc=replace(location,id=MemoryLocationId(self.scope,'addressed-'+token((location.id,address))))
        return self.engine._register_location(loc)

    def read(self,state,loc,guard,origin):
        self.validate_current()
        self.calls['read']+=1
        placeholder=self.engine.dag.make(ValueType.bv(loc.width_bits),SymbolicOp.MEMORY_READ,origin=origin,state=state,location=loc.id)
        return self.engine.read(ReadMemory(state,loc.id,placeholder,guard,origin),self.budget)

    def write(self,state,loc,value,guard,origin):
        self.validate_current()
        self.calls['write']+=1;self.calls['resolve_alias']+=1
        alias=self.engine.resolve_alias(state,loc,loc,self.budget)
        strong=alias.kind==AliasKind.MUST
        request=WriteMemory(state,loc.id,value,guard,UpdateKind.STRONG if strong else UpdateKind.WEAK,
            alias,origin,strong,strong)
        return self.engine.write(request,self.budget)

    def alias(self,state,a,b):
        self.validate_current()
        self.calls['resolve_alias']+=1;e=self.engine
        if not self._alias_cache_enabled:return e.resolve_alias(state,a,b,self.budget)
        if state not in e.versions:raise ValueError('Unknown memory version')
        same_scope(self.scope,a.id,b.id)
        if a.object_id is None or b.object_id is None:key=state,'unknown-object'
        else:
            if a.object_id not in e.objects or b.object_id not in e.objects:raise ValueError('Unregistered alias operand')
            key=(state,a.object_id,b.object_id,a.offset_lower,a.offset_upper,b.offset_lower,b.offset_upper,
                a.width_bits,b.width_bits,a.endian,b.endian,a.address_space,b.address_space,
                e.object_facts.get(a.object_id),e.object_facts.get(b.object_id))
        if key in self._alias_cache:
            self._alias_hits+=1;return self._alias_cache[key]
        self._alias_misses+=1;result=e.resolve_alias(state,a,b,self.budget)
        if len(self._alias_cache)<8192:self._alias_cache[key]=result
        return result

    def havoc(self,state,regions,reason,origin,guard=None):
        self.validate_current()
        self.calls['havoc']+=1;return self.engine.havoc(state,regions,reason,origin,guard)

    def definitions(self,read):
        self.validate_current()
        self.calls['resolve_definition']+=1;return self.engine.resolve_definition(read,self.budget)

    def read_definition(self,result,guard,origin):
        node=self.engine.dag.nodes[result]
        if node.op!=SymbolicOp.MEMORY_READ:raise ValueError('Definition query needs a versioned read leaf')
        return self.definitions(ReadMemory(node.state,node.location,result,guard,origin))

    def candidates(self,reference,limit=64):
        self.validate_current()
        root,resolver=self.engine.resolve(reference,self.budget)
        d=self.engine.dag;done={};stack=[(root,False)]
        while stack:
            ref,ready=stack.pop()
            if ref in done:continue
            n=d.nodes[ref]
            if not ready and n.operands:
                stack.append((ref,True));stack.extend((x,False) for x in n.operands if x not in done);continue
            value=d.constant_value(ref)
            if value is not None:values,top={value},False
            elif n.op==SymbolicOp.IF:
                left,right=done[n.operands[1]],done[n.operands[2]]
                values,top=left[0]|right[0],left[1] or right[1]
            elif n.operands:
                values=set();top=any(done[x][1] for x in n.operands)
                amount=1
                for x in n.operands:amount*=len(done[x][0])
                if amount>limit:raise BudgetExceeded('alias_candidates',limit,amount)
                for args in product(*(done[x][0] for x in n.operands)):
                    item=d._calculate(n,args)
                    if item is not None:values.add(item%(1<<n.type.bits) if n.type.kind!=TypeKind.BOOL else item)
            else:values,top=set(),True
            if len(values)>limit:raise BudgetExceeded('alias_candidates',limit,len(values))
            done[ref]=values,top
        return tuple(sorted(done[root][0])),done[root][1],tuple(resolver.assessments)

    def metrics(self):
        result={**self.engine.metrics(),'memory_port_calls':dict(self.calls)}
        if self._alias_cache_enabled:result.update(alias_cache_hits=self._alias_hits,alias_cache_misses=self._alias_misses,
            alias_cache_entries=len(self._alias_cache))
        return result
