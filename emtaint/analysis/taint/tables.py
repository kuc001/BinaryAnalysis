"""Old hsearch_r INSERT/FIND summaries, including its key-insensitive model.

The original Stack-ABI Load is consumed by argument binding. The remaining
Load(htab)+o / ENTRY.data path stays distinct from the htab pointer cell.
This is a may model of entry storage, never a precise hash-table execution.
"""
from __future__ import annotations
from dataclasses import dataclass
import hashlib
from emtaint.core import MemoryObject, MemoryObjectId
from emtaint.core.contracts import SymbolicExprId, ValueType
from emtaint.ir.canonical import CallEffect
from emtaint.memory import AccessRoot, Offset, Deref, UnknownOffset, SymbolicOp, AliasKind
from emtaint.memory.abstract_heap import ObjectCardinality, ObjectLifetime
from .demand_models import TaintDependency


@dataclass(frozen=True)
class TableRoot:
    binary:str
    kind:str
    value:object
    offset:int|None=0


class LegacyHashTables:
    def __init__(self, owner, bank):
        self.owner=owner
        self.bank=bank
        self.outputs={}
        self.reads=set()
        self.broad_reads=set()
        self.projections={}
        self.find_projections={}

    def root(self, reference, origin):
        d=self.owner
        p=d.port
        e=p.engine
        binary=p.scope.function.binary.sha256
        absolute=p.concrete(reference)
        if type(absolute) is int and e.address(absolute):return TableRoot(binary, 'global', absolute)
        binding=d.demand.address_binding(reference)
        if binding:
            root, offset=binding
            for index, argument in getattr(e, 'argument_roots', {}).items():
                if argument.object_id==root.object_id:return TableRoot(binary, 'argument', index, offset)
        return TableRoot(binary, 'unknown', origin)

    def bind_roots(self, root, call):
        d=self.owner
        p=d.port
        if root.kind!='argument':return (root,)
        result=[]
        for reference in d.argument(call, root.value):
            if root.offset is None:
                result.append(TableRoot(root.binary, 'unknown', 'Unknown table offset at '+call.origin))
                continue
            if root.offset:
                delta=p.constant(root.offset%(1<<p.engine.architecture.pointer_bits), p.type_of(reference), call.origin)
                reference=p.operation(SymbolicOp.ADD, p.type_of(reference), (reference, delta), call.origin)
            result.append(self.root(reference, call.origin))
        return tuple(dict.fromkeys(result))

    def write(self, root, dependencies, call):
        d=self.owner
        self.outputs[root]=d.union((self.outputs.get(root, ()), dependencies))
        for dependency in dependencies:
            if dependency.kind=='source':self.project(root, dependency, call)

    def read(self, root, call):
        d=self.owner
        self.reads.add(root)
        dependencies=self.bank.get(root)
        if root not in self.bank or root.kind=='unknown':self.broad_reads.add(root)
        if dependencies is None and self.bank:
            # Distinct roots do not prove disjoint pointed-to entry storage.
            dependencies=d.union(self.bank.values())
            dependencies=d.union((dependencies, (TaintDependency('unknown', 'Unresolved hsearch payload alias between table roots', uncertain=True),)))
        if not dependencies:return (TaintDependency('hash', root, uncertain=True),)
        for dependency in dependencies:
            if dependency.kind=='source':
                if d.active_sink is not None:d.partial_sources.add(dependency)
                self.project(root, dependency, call)
        return dependencies

    def find(self, root:TableRoot, call:CallEffect, retptr:SymbolicExprId)->tuple[TaintDependency, ...]:
        """Record old FIND's possible ``Store(Store(retptr)+4)`` path.

        The source belongs to ENTRY.data after two dereferences. It does not
        taint the pointer cell itself or assert a concrete hash-table match.
        """
        dependencies=self.read(root, call)
        d=self.owner
        p=d.port
        e=p.engine
        ret_location=d.location(retptr, call.origin)
        if ret_location.object_id is None or ret_location.offset_lower!=ret_location.offset_upper:
            d.pending.append((call.origin, 'hsearch FIND retptr address unresolved; pointed data remains may'))
            return dependencies
        ret_root=e.roots[ret_location.object_id]
        bits=e.architecture.pointer_bits
        path=(Offset(ret_location.offset_lower), Deref(bits, bits, e.architecture.endian),
            Offset(bits//8), Deref(bits, bits, e.architecture.endian))
        for dependency in dependencies:
            if dependency.kind!='source':continue
            key=root, dependency, call.origin, ret_location.object_id, ret_location.offset_lower
            if key in self.find_projections:continue
            table_binding=self.projections[root, dependency, call.origin]
            self.find_projections[key]=d.regions.bind(table_binding.fact.memory_version,
                table_binding.location, dependency.value, call.origin,
                guard=table_binding.fact.guard, constraints=dependency.constraints,
                access_root=ret_root, segments=path,
                provenance=('Old hsearch_r.find_data Store(Store(retptr)+4) may transfer',
                    'Table source remains separate from retptr pointer value', repr(root)))
        return dependencies

    def project(self, root, dependency, call):
        d=self.owner
        p=d.port
        e=p.engine
        key=root, dependency, call.origin
        if key in self.projections:return
        token=hashlib.sha256(repr(root).encode()).hexdigest()
        obj=MemoryObjectId.unknown(p.scope.function.binary, 'hsearch-entry-storage', 'Opaque hash entry storage', token)
        payload=AccessRoot(obj, 'unknown', 'default', call.origin)
        if obj not in e.objects:e.add_object(MemoryObject(obj, 'Original hsearch_r key-insensitive entry abstraction'), payload,
            ObjectCardinality.UNKNOWN, ObjectLifetime.UNKNOWN, ('Possible entry payload loaded from '+repr(root),))
        location=e.location(e.roots[obj], None, 32, e.architecture.endian, call.origin)
        value=p.symbol('hsearch-data-source:'+str(dependency.value), ValueType.bv(32), call.origin)
        guards=d.demand.value(call.guard)
        guard=guards[0] if len(guards)==1 else p.unknown(ValueType.boolean(), call.origin, 'Hash call guard alternatives')
        state=p.write(d.demand.initial.memory, location, value, guard, call.origin).state
        access_root=e.roots[obj]
        prefix=()
        if root.kind=='global':
            binding=e.address(root.value)
            if binding:
                access_root, offset=binding
                prefix=(Offset(offset), Deref(32, 32, e.architecture.endian))
        elif root.kind=='argument' and root.offset is not None:
            access_root=e.argument_roots[root.value]
            prefix=(Offset(root.offset), Deref(32, 32, e.architecture.endian))
        segments=prefix+(UnknownOffset(None, None, 'Original hsearch_r entry offset o'), Deref(32, 32, e.architecture.endian))
        self.projections[key]=d.regions.bind(state, location, dependency.value, call.origin, guard=guard,
            constraints=dependency.constraints, access_root=access_root, segments=segments,
            provenance=('Legacy hsearch_r INSERT/FIND; key is ignored by the original algorithm',
                'Entry storage is a possible pointee, not the htab pointer cell', repr(root), repr(dependency.guards)))

    def data_field_query(self, reference, call):
        """Match old Store(Store(retptr)+4), preserving both indirections."""
        d=self.owner
        p=d.port
        e=p.engine
        def strip(ref):
            while True:
                node=e.dag.nodes[ref]
                if node.op==SymbolicOp.COPY:
                    ref=node.operands[0]
                    continue
                if node.op==SymbolicOp.ADD:
                    a, b=node.operands
                    if e.dag.constant_value(a)==0:
                        ref=b
                        continue
                    if e.dag.constant_value(b)==0:
                        ref=a
                        continue
                return ref
        reference=strip(reference)
        node=e.dag.nodes[reference]
        if node.op!=SymbolicOp.ADD:return False
        left, right=node.operands
        if e.dag.constant_value(right)!=4:
            if e.dag.constant_value(left)!=4:return False
            left=right
        pointer=strip(left)
        if pointer not in d.demand.loads:return False
        address=d.demand.loads[pointer][0]
        queried=d.location(address, call.origin)
        return any(p.alias(d.demand.initial.memory, queried, d.location(value, call.origin)).kind!=AliasKind.NO
            for value in d.argument(call, 3))
