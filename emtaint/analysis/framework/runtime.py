"""P6 session-owned dependency caches, graph updates and stale-reference checks.

P2's global graph stamp still invalidates raw P3 scoped handles. Unaffected
scalar metadata caches survive by a per-function epoch. Rich scoped values must
be rebuilt/rebased explicitly, never silently reused as current heap states.
"""
from dataclasses import dataclass,fields,is_dataclass
from enum import Enum
from emtaint.core import AnalysisSession,ContextId
from emtaint.graph import CallGraph,CallEdge,TargetKind


class StaleAnalysis(ValueError):pass


@dataclass(frozen=True)
class AnalysisHandle:
    session: str
    revision: int
    function: object
    context: ContextId


class AnalysisRuntime:
    NAMESPACES=frozenset(('heap','alias','sse','apg','summary','facts','result'))
    INFERRED_PREFIX='P6 derived CIR target: '

    def __init__(self,program):
        self.session=AnalysisSession(program);self._cache={};self.epochs={f.id:0 for f in program.functions}
        self.pending=set();self.events=[]
        self.ports={}
        self.active=set();self.metadata_invalidated=set();self._recipes={}

    def handle(self,function,context):
        self.session.program.function(function);self.session.register_context(context)
        self.active.add(function)
        return AnalysisHandle(self.session.stamp.session_id,self.session.stamp.state_revision,function,context)

    def validate(self,handle):
        if (handle.session,handle.revision)!=(self.session.stamp.session_id,self.session.stamp.state_revision):
            raise StaleAnalysis('Graph/object revision changed; scoped state is stale')

    def put(self,namespace,function,context,key,payload):
        if namespace not in self.NAMESPACES:raise ValueError('Unknown cache family')
        from emtaint.core.session import portable_value
        portable_value(payload)
        self.session.program.function(function);self.session.register_context(context)
        self.active.add(function)
        if len(self._cache)>=self.session.budgets.max_cache_entries and (namespace,function,context,key) not in self._cache:
            raise ValueError('P6 cache budget exhausted; incomplete')
        self._cache[namespace,function,context,key]=(self.epochs[function],payload)

    def get(self,namespace,function,context,key):
        entry=self._cache.get((namespace,function,context,key))
        return entry[1] if entry is not None and entry[0]==self.epochs[function] else None

    def _affected(self,seeds,graphs):
        affected=set(seeds)
        while True:
            new=affected|{edge.site.function for graph in graphs for edge in graph.edges if edge.target in affected}
            if new==affected:return frozenset(affected)
            affected=new

    def _invalidate(self,affected,reason):
        for function in affected:self.epochs[function]+=1
        self._cache={key:value for key,value in self._cache.items() if key[1] not in affected}
        self.ports={key:value for key,value in self.ports.items() if key[0] not in affected}
        self._recipes={key:value for key,value in self._recipes.items() if key[0] not in affected}
        self.pending.update(set(affected)&self.active)
        self.metadata_invalidated.update(set(affected)-self.active)
        self.events.append((reason,tuple(sorted(f.rva for f in affected)),self.session.stamp.state_revision))

    def replace_cfg(self,cfg):
        if cfg==self.session.cfg(cfg.function):return frozenset()
        self.session.replace_cfg(cfg);affected=self._affected((cfg.function,),(self.session.cg,))
        self._invalidate(affected,'CFG changed');return affected

    def add_call_edge(self,edge):
        return self.add_call_edges((edge,))

    def invalidate_dependencies(self,functions,reason):
        """Invalidate semantic summaries and their real reverse-CG callers."""
        functions=frozenset(functions)
        if not functions:return frozenset()
        for function in functions:self.session.invalidate_semantics(function,reason)
        affected=self._affected(functions,(self.session.cg,))
        self._invalidate(affected,reason)
        return affected

    def add_call_edges(self,edges):
        old=self.session.cg
        edges=frozenset(edges)-old.edges
        if not edges:return frozenset()
        # Retain unresolved edges until exhaustive, independently justified
        # resolution; a may-candidate cannot erase the unknown remainder.
        graph=CallGraph(old.nodes,old.edges|edges,old.status,old.reason)
        self.session.replace_cg(graph)
        affected=self._affected(tuple(edge.site.function for edge in edges), (old,graph))
        self._invalidate(affected,'CG target added');return affected

    def replace_inferred_call_edges(self,sites,edges):
        """Replace stale derived facts while preserving static/imported proof."""
        old=self.session.cg;sites=frozenset(sites)
        retained=frozenset(e for e in old.edges if not(e.site in sites and e.reason.startswith(self.INFERRED_PREFIX)))
        graph=CallGraph(old.nodes,retained|frozenset(edges),old.status,old.reason)
        if graph==old:return frozenset()
        self.session.replace_cg(graph)
        changed=old.edges^graph.edges
        affected=self._affected(tuple(e.site.function for e in changed),(old,graph))
        self._invalidate(affected,'CG derived facts replaced');return affected

    def recipe_get(self,function,context):
        entry=self._recipes.get((function,context))
        return entry[1] if entry is not None and entry[0]==self.epochs[function] else None

    def recipe_put(self,function,context,recipe):
        """Only detached immutable recipes survive global graph revisions."""
        from emtaint.core.contracts import ScopedId
        if recipe.function!=function:raise ValueError('Recipe belongs to a different function')
        pending=[recipe];seen=set()
        while pending:
            value=pending.pop()
            if isinstance(value,ScopedId):raise ValueError('Recipe cannot retain scoped memory/SSE/APG IDs')
            if value is None or type(value) in (int,str,bool) or isinstance(value,Enum):continue
            if id(value) in seen:continue
            seen.add(id(value))
            if type(value) is tuple:pending.extend(value)
            elif is_dataclass(value) and value.__dataclass_params__.frozen and type(value).__module__.startswith('emtaint.'):
                pending.extend(getattr(value,f.name) for f in fields(value))
            else:raise TypeError('Recipe must be detached immutable analysis metadata')
        self.session.program.function(function);self.session.register_context(context)
        self.active.add(function)
        old=self.recipe_get(function,context)
        if old==recipe:return frozenset()
        affected=frozenset()
        if old is not None:
            self.session.invalidate_semantics(function,'Procedure recipe changed')
            affected=self._affected((function,),(self.session.cg,))
            self._invalidate(affected,'Procedure recipe changed')
        self._recipes[function,context]=(self.epochs[function],recipe)
        self.session.summary_put(function,context,('detached-procedure-recipe',len(recipe.nodes),len(recipe.returns)))
        return affected

    def bind_port(self,port,function,context):
        port.scope.assert_current(self.session)
        if port.scope.function!=function or port.scope.context!=context:raise ValueError('Port function/context mismatch')
        handle=self.handle(function,context)
        port.validate_current=lambda:self.validate(handle)
        self.ports[function,context]=port

    def memory_put(self,namespace,handle,memory,key,payload):
        self.validate(handle);memory.scope.assert_current(self.session)
        if memory.scope.function!=handle.function or memory.scope.context!=handle.context:
            raise ValueError('Cache memory/context mismatch')
        self.put(namespace,handle.function,handle.context,(memory,key),payload)

    def memory_get(self,namespace,handle,memory,key):
        self.validate(handle);memory.scope.assert_current(self.session)
        return self.get(namespace,handle.function,handle.context,(memory,key))
