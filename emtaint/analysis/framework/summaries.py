"""Scoped-DAG-free procedure recipes for legacy use/def/return substitution.

Recipes contain typed values and local integer edges. They are instantiated
through the caller's memory port; callee MemoryVersion/SSE IDs never escape.
This is an analysis-private representation, not a change to CIR wire v1.
"""
from dataclasses import dataclass
from itertools import product
from emtaint.core import MemoryObject, MemoryObjectId
from emtaint.core.contracts import ValueType
from emtaint.memory import AccessRoot, AliasKind, SymbolicOp
from emtaint.memory.abstract_heap import ObjectCardinality, ObjectLifetime
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.ir.canonical import CallEffect, UnknownEffect, HavocEffect


@dataclass(frozen=True)
class SummaryNode:
    type:object
    op:str
    operands:tuple=()
    value:object=None
    params:tuple=()
    origin:str=''
    endian:object=None


@dataclass(frozen=True)
class SummaryRead:
    width_bits:int
    endian:object
    origin:str


@dataclass(frozen=True)
class SummaryStore:
    addresses:tuple
    values:tuple
    width_bits:int
    endian:object
    origin:str
    guards:tuple=()
    must_execute:bool=False
    no_unknown_after:bool=False


@dataclass(frozen=True)
class ProcedureRecipe:
    function:object
    nodes:tuple
    returns:tuple
    stores:tuple
    argument_uses:tuple
    provenance:tuple
    write_regions:tuple
    unknown_effects:bool=False

    def instantiate(self, caller, call, depth=0):
        """Legacy _update_expr_from_callees with callsite argument aliases."""
        done=self.evaluate(caller, call, self.returns, depth)
        if self.write_regions:caller.notes.append('Callee recipe return candidates retain unproved memory side effects')
        return caller.union(done[x] for x in self.returns)

    def position(self, caller, call):
        if call.results and call.results[0].id in caller.defs:return caller.defs[call.results[0].id][:2]
        for block in caller.function.blocks:
            for index, effect in enumerate(block.effects):
                if effect==call:return block.id, index
        raise ValueError('Recipe call is outside the caller CIR')

    def evaluate(self, caller, call, roots, depth):
        p=caller.port
        done={}
        block, index=self.position(caller, call)
        needed=set()
        todo=list(roots)
        while todo:
            node_id=todo.pop()
            if node_id in needed:continue
            needed.add(node_id)
            todo.extend(self.nodes[node_id].operands)
        for node_id, node in enumerate(self.nodes):
            if node_id not in needed:continue
            caller.tick(depth)
            if node.op=='argument':
                register_count=len(call.abi.argument_registers or ('r0', 'r1', 'r2', 'r3'))
                result=(caller.value(call.arguments[node.value], depth+1) if node.value<len(call.arguments) else
                        caller.stack_argument(call, node.value-register_count, node.type.bits, depth+1) if node.value>=register_count else
                        (p.unknown(node.type, call.origin, 'Unavailable callee register argument'),))
                caller.rules.add('legacy._initialize_callsite_arguments/use-def')
            elif node.op=='register':
                result=caller.register(block, index, node.value, node.type.bits, depth+1)
            elif node.op=='constant':result=(p.constant(node.value, node.type, call.origin),)
            elif node.op=='symbol':result=(p.symbol(node.value, node.type, call.origin),)
            elif node.op=='allocation':
                engine=p.engine
                cardinality = (
                    caller.allocation_cardinality(call)
                    if hasattr(caller, 'allocation_cardinality')
                    else ObjectCardinality.SUMMARY
                )
                object_id=MemoryObjectId.heap(
                    call.site.point, engine.scope.context
                )
                root=engine.roots.get(object_id)
                if root is None:
                    existing=tuple(engine.objects)
                    root=AccessRoot(
                        object_id, 'heap', 'default', call.origin
                    )
                    engine.add_object(
                        MemoryObject(object_id, 'Modeled allocator return'),
                        root,
                        cardinality,
                        ObjectLifetime.ALLOCATED,
                        (
                            'Fresh live allocation at modeled callsite',
                            'At most once per analysis invocation'
                            if cardinality == ObjectCardinality.SINGLETON
                            else 'Callsite may allocate multiple dynamic objects',
                        ),
                    )
                    for other in existing:
                        engine.prove_disjoint(
                            object_id,
                            other,
                            'Fresh allocator return is disjoint from live objects',
                        )
                value=p.symbol(
                    'allocation:'+object_id.token,
                    node.type,
                    call.origin,
                )
                bindings=getattr(caller, 'allocation_bindings', None)
                if bindings is None:
                    bindings={}
                    caller.allocation_bindings=bindings
                bindings[value]=(root, 0)
                result=(value,)
            elif node.op=='unknown':result=(p.unknown(node.type, call.origin, str(node.value)),)
            elif node.op=='read':
                query=SummaryRead(node.type.bits, node.endian, call.origin)
                result=caller.union(caller.read(block, index, address, query, depth+1) for address in done[node.operands[0]])
            else:
                groups=[done[x] for x in node.operands]
                amount=1
                for group in groups:amount*=len(group)
                if amount>caller.budget.alternatives:raise DemandLimit('Summary argument/return product budget', dimension='alternatives')
                result=caller.union((p.operation(SymbolicOp(node.op), node.type, args, call.origin, node.params),)
                                    for args in product(*groups))
            done[node_id]=result
        caller.rules.add('legacy._update_expr_from_callees/instantiated-recipe')
        return done

    def definitions(self, caller, call, depth):
        roots=tuple(x for store in self.stores for x in store.addresses+store.values+store.guards)
        done=self.evaluate(caller, call, roots, depth)
        p=caller.port
        result=[]
        for store in self.stores:
            guards=caller.union(done[x] for x in store.guards) if store.guards else (p.constant(True, ValueType.boolean(), call.origin),)
            for address in caller.union(done[x] for x in store.addresses):
                for value in caller.union(done[x] for x in store.values):
                    for guard in guards:
                        if not store.must_execute:
                            path=p.symbol('callee-store-path:'+call.origin+':'+store.origin, ValueType.boolean(), call.origin)
                            guard=p.operation(SymbolicOp.IF, ValueType.boolean(),
                                (path, guard, p.constant(False, ValueType.boolean(), call.origin)), call.origin)
                        result.append((store, address, value, guard))
                        if len(result)>caller.budget.alternatives:raise DemandLimit('Callee definition substitution budget', dimension='alternatives')
        return tuple(result)

    def addresses(self, caller, call, store, depth):
        done=self.evaluate(caller, call, store.addresses, depth)
        return caller.union(done[x] for x in store.addresses)

    def stored_values(self, caller, call, store, depth):
        value_roots=tuple(
            root for root in store.values
            if not self._disproved_may_store_unknown(
                caller, call, store, root, depth
            )
        )
        done=self.evaluate(caller, call, value_roots+store.guards, depth)
        p=caller.port
        guards=caller.union(done[x] for x in store.guards) if store.guards else (p.constant(True, ValueType.boolean(), call.origin),)
        result=[]
        for value in caller.union(done[x] for x in value_roots):
            for guard in guards:
                if not store.must_execute:
                    path=p.symbol('callee-store-path:'+call.origin+':'+store.origin, ValueType.boolean(), call.origin)
                    guard=p.operation(SymbolicOp.IF, ValueType.boolean(),
                        (path, guard, p.constant(False, ValueType.boolean(), call.origin)), call.origin)
                result.append((value, guard))
        return tuple(result)

    def _disproved_may_store_unknown(
            self, caller, call, store, root, depth):
        """Reject a callee MayAlias branch disproved after call binding."""

        node_id=root
        while (
                self.nodes[node_id].op=='copy'
                and len(self.nodes[node_id].operands)==1):
            node_id=self.nodes[node_id].operands[0]
        node=self.nodes[node_id]
        if not (
                node.op=='unknown'
                and str(node.value).startswith(
                    'MayAlias/partial/guarded reaching store')):
            return False
        position=next((
            index for index, candidate in enumerate(self.stores)
            if candidate is store
        ), None)
        if position is None or position==0:
            return False
        reads=[]
        seen=set()
        todo=[candidate for candidate in store.values if candidate!=root]
        while todo:
            candidate=todo.pop()
            if candidate in seen:
                continue
            seen.add(candidate)
            candidate_node=self.nodes[candidate]
            if candidate_node.op=='read':
                reads.append(candidate_node)
            todo.extend(candidate_node.operands)
        if not reads:
            return False
        engine=caller.port.engine
        for earlier in self.stores[:position]:
            earlier_addresses=self.addresses(caller, call, earlier, depth+1)
            for read in reads:
                read_addresses=self.evaluate(
                    caller, call, read.operands, depth+1
                )[read.operands[0]]
                for earlier_address in earlier_addresses:
                    earlier_binding=caller.address_binding(earlier_address)
                    if earlier_binding is None:
                        return False
                    earlier_location=engine.location(
                        *earlier_binding,
                        earlier.width_bits,
                        earlier.endian,
                        call.origin,
                    )
                    for read_address in read_addresses:
                        read_binding=caller.address_binding(read_address)
                        if read_binding is None:
                            return False
                        read_location=engine.location(
                            *read_binding,
                            read.type.bits,
                            read.endian,
                            call.origin,
                        )
                        alias=caller.port.alias(
                            caller.initial.memory,
                            earlier_location,
                            read_location,
                        )
                        if alias.kind!=AliasKind.NO:
                            return False
        return True


def compile_recipe(demand, returns, *, stores=(), provenance=()):
    """Export a finite shared recipe; every read keeps its separate address."""
    p=demand.port
    dag=p.engine.dag
    nodes=[]
    mapped={}
    visiting=set()
    argument_uses=set()
    p.validate_current()
    def visit(reference):
        if reference in mapped:return mapped[reference]
        n=dag.nodes[reference]
        if reference in visiting:
            node=SummaryNode(n.type, 'unknown', value='Unresolved recursive callee value', origin=n.origin)
        else:
            visiting.add(reference)
            if reference in demand.loads:
                address, width, endian, origin=demand.loads[reference]
                node=SummaryNode(n.type, 'read', (visit(address),), origin=origin, endian=endian)
            elif n.op==SymbolicOp.MEMORY_READ:
                resolved, _=p.engine.resolve(reference, p.budget)
                if resolved!=reference:
                    mapped[reference]=visit(resolved)
                    visiting.remove(reference)
                    return mapped[reference]
                node=SummaryNode(n.type, 'unknown', value='Unresolved callee memory definition', origin=n.origin)
            elif n.op==SymbolicOp.SYMBOL:
                if n.value.startswith('argument:'):
                    index=int(n.value.split(':')[1])
                    argument_uses.add(index)
                    node=SummaryNode(n.type, 'argument', value=index, origin=n.origin)
                elif n.value.startswith('entry:'):
                    node=SummaryNode(n.type, 'register', value=n.value.split(':', 1)[1], origin=n.origin)
                elif n.value.startswith('legacy-cycle:'):
                    node=SummaryNode(n.type, 'unknown', value='Unresolved callee induction definition', origin=n.origin)
                elif n.value.startswith('allocation:'):
                    node=SummaryNode(n.type, 'allocation', origin=n.origin)
                else:node=SummaryNode(n.type, 'symbol', value=n.value, origin=n.origin)
            else:
                node=SummaryNode(n.type, n.op.value, tuple(visit(x) for x in n.operands), n.value, n.params, n.origin)
            visiting.remove(reference)
        identifier=len(nodes)
        nodes.append(node)
        mapped[reference]=identifier
        return identifier
    roots=tuple(dict.fromkeys(visit(x) for x in returns))
    definitions=[]
    for effect, addresses, values in stores:
        guards=tuple(visit(x) for x in demand.value(effect.guard))
        must=(len(demand.function.blocks)==1 and getattr(effect.guard, 'value', None) is True)
        definitions.append(SummaryStore(tuple(visit(x) for x in addresses), tuple(visit(x) for x in values),
            effect.width_bits, effect.endian, effect.origin, guards, must))
    unknown=any(bool(e.footprint.write_regions) if isinstance(e, CallEffect) else
        bool(e.may_write_regions) if isinstance(e, UnknownEffect) else bool(e.regions)
        for b in demand.function.blocks for e in b.effects if isinstance(e, (CallEffect, UnknownEffect, HavocEffect)))
    return ProcedureRecipe(demand.function.function_id, tuple(nodes), roots, tuple(definitions), tuple(sorted(argument_uses)),
        tuple(provenance), ('*',) if definitions or unknown else (), unknown)
