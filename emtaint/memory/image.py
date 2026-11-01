"""Immutable ET_EXEC initial bytes, interpreted within normal memory versions.

The frontend supplies load segments; no file access or native IR enters here.
Unknown writes/havoc still flow through the P5 definition resolver.
"""
from emtaint.core import MemoryObject,MemoryObjectId
from emtaint.core.contracts import ValueType
from .engine import PythonMemoryEngine
from .memory_version import DefinitionResolver
from .state import InitialMemory,SymbolicOp
from .access_path import AccessRoot
from .abstract_heap import ObjectCardinality,ObjectLifetime
from .query_port import QueryBudget
from .policies import BudgetExceeded
from .read_index import ReadIndex,records_for
from collections import OrderedDict


class ImageMemoryEngine(PythonMemoryEngine):
    def __init__(self,scope,architecture,origins,segments,budgets,*,initial_policy='readonly-at-entry',cache_resolutions=False):
        super().__init__(scope,architecture,origins,budgets)
        if initial_policy not in ('readonly-at-entry','legacy-loader-snapshot'):
            raise ValueError('Explicit supported initial-memory policy required')
        self.initial_policy=initial_policy
        self.cache_resolutions=cache_resolutions;self._resolution_cache=OrderedDict();self._resolution_hits=0;self._resolution_misses=0
        self._nonconstant_read_shortcuts=0
        # SSE nodes are immutable. Reuse only completed expressions whose
        # selected evaluation contains no MemoryRead or memory evidence.
        self._pure_values=OrderedDict();self._pure_value_hits=0
        if cache_resolutions:self.reads=ReadIndex(self.reads)
        self.segments=tuple(segments)
        self.image_base=min((s[0] for s in self.segments),default=0)
        self.segment_roots=[]
        for base,data,memsz,flags in self.segments:
            if type(data) is not bytes or len(data)>memsz or base<0:raise ValueError('Invalid immutable image segment')
            obj=MemoryObjectId.global_object(scope.function.binary,'ELF-PT_LOAD',base-self.image_base)
            root=AccessRoot(obj,'global','default',self.origins[0].id)
            self.add_object(MemoryObject(obj,'ET_EXEC mapped initial image',memsz),root,
                ObjectCardinality.SINGLETON,ObjectLifetime.STATIC,('File-backed ET_EXEC load mapping; zero-filled tail',))
            self.segment_roots.append(root)
        for i,a in enumerate(self.segment_roots):
            for j,b in enumerate(self.segment_roots[:i]):
                aa,bb=self.segments[i],self.segments[j]
                if aa[0]+aa[2]<=bb[0] or bb[0]+bb[2]<=aa[0]:
                    self.prove_disjoint(a.object_id,b.object_id,'Disjoint ELF virtual address intervals')

    def address(self,absolute):
        for root,(base,data,memsz,flags) in zip(self.segment_roots,self.segments):
            if base<=absolute<base+memsz:return root,absolute-base
        return None

    def resolve(self,reference,budget=QueryBudget(),*,initial_policy=None):
        policy=self.initial_policy if initial_policy is None else initial_policy
        if policy not in ('readonly-at-entry','legacy-loader-snapshot'):raise ValueError('Unknown image policy')
        class ImageResolver(DefinitionResolver):
            def byte(self,state,loc,index,depth=0):
                if isinstance(self.e.versions[state].definition,InitialMemory):
                    cell=self.byte_location(loc,index)
                    frame=getattr(self.e,'entry_frame_inputs',{}).get(cell.object_id)
                    if frame is not None and cell.offset_lower==cell.offset_upper and cell.offset_lower is not None:
                        word=self.e.architecture.pointer_bits//8;offset=cell.offset_lower
                        if 0<=offset<len(frame)*word:
                            value=frame[offset//word];byte=offset%word
                            low=byte*8 if self.e.architecture.endian.value=='little' else (word-1-byte)*8
                            self.step(depth);self.definitions.add(state)
                            return self.d.operation(SymbolicOp.EXTRACT,ValueType.bv(8),(value,),loc.origin,(low+7,low))
                    for root,segment in zip(self.e.segment_roots,self.e.segments):
                        if cell.object_id==root.object_id and cell.offset_lower==cell.offset_upper and cell.offset_lower is not None:
                            offset=cell.offset_lower;_,data,memsz,flags=segment
                            # Function entry is not process startup. Writable
                            # globals/BSS may already have changed in callers.
                            if 0<=offset<memsz and (not flags & 2 or policy=='legacy-loader-snapshot'):
                                self.step(depth);self.definitions.add(state)
                                value=data[offset] if offset<len(data) else 0
                                return self.d.constant(value,8,loc.origin)
                return super().byte(state,loc,index,depth)
        resolver=ImageResolver(self,budget)
        if self.cache_resolutions and reference in self._pure_values:
            return resolver.expression(reference),resolver
        cache_key=(reference,budget,policy,tuple(self.object_facts.items()),
            tuple(getattr(self,'entry_frame_inputs',{}).items())) if self.cache_resolutions else None
        cached=self._resolution_cache.get(cache_key) if self.cache_resolutions else None
        if cached is not None and all(records_for(self.reads,ref)==records for ref,records in cached[3]):
            self.accounting.charge('worklist_iterations');self._resolution_hits+=1
            self._resolution_cache.move_to_end(cache_key)
            value,definitions,assessments,dependencies=cached
            resolver.memo[reference]=value;resolver.definitions=set(definitions);resolver.assessments=list(assessments)
            resolver.read_dependencies=dict(dependencies)
            return value,resolver
        self._resolution_misses+=1
        try:
            value=resolver.expression(reference)
            if self.cache_resolutions:
                self._resolution_cache[cache_key]=(value,frozenset(resolver.definitions),tuple(resolver.assessments),tuple(resolver.read_dependencies.items()))
                self._resolution_cache.move_to_end(cache_key)
                if len(self._resolution_cache)>128:self._resolution_cache.popitem(last=False)
            return value,resolver
        except BudgetExceeded as error:self._notes.append(error.assessment);raise

    def metrics(self):
        result=super().metrics()
        if self.cache_resolutions:result.update(resolution_cache_hits=self._resolution_hits,resolution_cache_misses=self._resolution_misses,
            resolution_cache_entries=len(self._resolution_cache),read_index_records=len(self.reads),
            nonconstant_read_shortcuts=self._nonconstant_read_shortcuts,
            pure_value_hits=self._pure_value_hits,pure_value_entries=len(self._pure_values))
        return result

    def _provably_nonconstant_read(self,reference):
        """Exact negative constant query; definition/alias APIs stay unchanged.

        P5 cannot MustAlias a missing/ranged location or summary instance.
        Those reads retain an unconstrained initial-byte alternative through
        every may/weak write. Exclude exact image/frame initial values, which
        can be concrete. No SSE value, memory definition or taint is replaced.
        """
        if not self.cache_resolutions:return False
        node=self.dag.nodes[reference]
        if node.op!=SymbolicOp.MEMORY_READ:return False
        loc=self.locations[node.location];point=loc.offset_lower is not None and loc.offset_lower==loc.offset_upper
        fact=self.object_facts.get(loc.object_id)
        no_must=loc.object_id is None or not point or (fact is not None and fact.cardinality!=ObjectCardinality.SINGLETON)
        known_initial=point and (any(root.object_id==loc.object_id for root in self.segment_roots)
            or loc.object_id in getattr(self,'entry_frame_inputs',{}))
        if not no_must or known_initial:return False
        guards={read.guard for read in records_for(self.reads,reference)}
        if len(guards)>1:raise ValueError('One MemoryRead ID cannot describe distinct guarded definitions')
        for guard in guards:
            if guard is not None:
                if self.dag.nodes[guard].type!=ValueType.boolean():raise ValueError('Memory read guard must be Boolean')
        self.accounting.charge('worklist_iterations');self._nonconstant_read_shortcuts+=1
        return True

    def constant_value(self,reference):
        if self._provably_nonconstant_read(reference):return None
        return super().constant_value(reference)

    def runtime_constant_value(self,reference):
        # Loader bytes are candidates for GOT/table reconstruction, not proof
        # of mutable globals at an arbitrary function entry. Explicit versioned
        # writes still resolve through the same definition chain.
        if self._provably_nonconstant_read(reference):return None
        resolved,_=self.resolve(reference,initial_policy='readonly-at-entry')
        return self.dag.constant_value(resolved)
