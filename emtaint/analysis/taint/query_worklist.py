"""Fair independent demands over the original immutable CIR cutoffs.

Transfers are unchanged. Global budgets stay authoritative; local shares yield
an explicit frontier and one retry after other demands have made progress.
"""
from collections import deque
from dataclasses import dataclass, replace
import logging
import time
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.debugging import log_event


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class TaintQuery:
    id:str
    kind:str
    block:object
    index:int
    effect:object
    payload:object=None


def interleave_inherited_prefix(owner, queries):
    """Share the first inherited-sink priority band across callsites.

    The demand scheduler has already placed this band before local copy calls.
    Only its contiguous callsite groups may be interleaved; later priorities,
    returns, and outputs retain their original order and budget semantics.
    """
    queries=tuple(queries)
    cursor=0
    while cursor<len(queries) and queries[cursor].kind=='source':cursor+=1
    def inherited(query):
        return query.kind=='call' and any(owner.summaries[callee].sinks
            for callee in owner.call_functions(query.effect) if callee in owner.summaries)
    while cursor<len(queries) and not inherited(queries[cursor]):
        if queries[cursor].kind!='call':return queries
        origin=queries[cursor].effect.origin
        while cursor<len(queries) and queries[cursor].effect.origin==origin:cursor+=1
    start=cursor
    groups=[]
    while cursor<len(queries):
        first=queries[cursor]
        if not inherited(first):break
        end=cursor+1
        while end<len(queries) and queries[end].effect.origin==first.effect.origin:end+=1
        groups.append(deque(queries[cursor:end]))
        cursor=end
    if len(groups)<2:return queries
    ordered=list(queries[:start])
    while groups:
        remaining=[]
        for group in groups:
            ordered.append(group.popleft())
            if group:remaining.append(group)
        groups=remaining
    return tuple(ordered)+queries[cursor:]


def run_queries(owner, queries, max_attempts=2):
    from .demand import TaintDependency, SinkRequirement, BufferDestination, dependency_order
    from emtaint.procedures.legacy import lookup
    todo=deque((query, 1) for query in interleave_inherited_prefix(owner, queries))
    retries=[]
    partials={}
    sources={}
    def retry_cost(item):
        query, _=item
        if query.kind=='call':return 0, 0, query.id
        if query.kind=='sink':
            sink=query.payload
            return 1, len(sink.dependencies)+sum(len(recipe.value.nodes) for dep in sink.dependencies for recipe in dep.recipes), query.id
        return 2, 0, query.id
    while todo:
        # Give every first-pass call/sink demand its normal priority, but do
        # not strand their one allowed retry behind the much larger
        # output/global-output tail.  Return and scalar-return first passes
        # stay ahead of retries because they can populate shared argument and
        # scalar caches needed by an inherited sink's second attempt.  The
        # unbounded output tail remains after retries, so a wall deadline there
        # cannot make a retry unreachable.
        if retries and todo[0][0].kind in ('output', 'global_output'):
            for item in reversed(sorted(retries, key=retry_cost)):todo.appendleft(item)
            retries.clear()
        query, attempt=todo.popleft()
        retained=sources.get(query.id, ())
        if (attempt>1 and query.kind=='sink' and
                len(retained)>owner.max_dependencies):
            # The first pass has already proved these caller-bound Sources.
            # Re-expanding the same formal buffer frontier can consume every
            # retry share before an independent bounded-copy length channel is
            # reached.  Resume from the proved checkpoint and keep an Unknown
            # tail for the alternatives that were not enumerated.  bind_sink
            # will conservatively recover the over-cap buffer set and then
            # proceed to length binding without raising global budgets.
            frontier=TaintDependency('unknown',
                'Prior buffer frontier incomplete; retry resumes length binding',
                uncertain=True)
            query=replace(query, payload=replace(query.payload,
                dependencies=retained+(frontier,)))
        owner.clear_query_limits()
        owner.frontier=query.effect.origin
        owner.current_query=query.id
        owner.active_sink=None
        owner.partial_sources=set()
        owner.query_sources=set()
        owner.active_global_output=None
        if query.kind=='sink':
            sink=query.payload
            owner.active_sink=replace(sink, destinations=tuple(BufferDestination('unknown', 'Unbound callee destination', None)
                if destination.kind=='argument' else destination for destination in sink.destinations))
        handled=False
        started=time.monotonic()
        taint_start=owner.steps
        scalar_start=owner.demand.steps
        memory_start=owner.port.engine.accounting.counts['worklist_iterations']
        def cost():
            return {'kind':query.kind, 'origin':query.effect.origin,
                'taint_steps':owner.steps-taint_start,
                'scalar_steps':owner.demand.steps-scalar_start,
                'memory_work':owner.port.engine.accounting.counts['worklist_iterations']-memory_start,
                'seconds':time.monotonic()-started}
        log_event(LOGGER, 'taint.query.started', query_id=query.id, kind=query.kind,
            origin=query.effect.origin, attempt=attempt, remaining=len(todo))
        try:
            owner.tick()
            owner.queries_remaining=len(todo)+1
            owner.begin_query(query)
            owner.execute_query(query)
            # A completed refinement can replace its budget-only Unknown. The
            # known sources observed on the interrupted walk must still survive.
            retained=sources.get(query.id, ())
            if owner.active_sink is not None and retained:
                owner.add_sink(replace(owner.active_sink, dependencies=owner.union((retained, owner.active_sink.dependencies))))
            for index in partials.get(query.id, ()):owner.completed_sinks[index]=None
            owner.query_pending.pop(query.id, None)
            if attempt>1:owner.query_history.append({'id':query.id, 'attempt':attempt, 'status':'completed-after-retry', **cost()})
            log_event(LOGGER, 'taint.query.completed', query_id=query.id, attempt=attempt, **cost())
            handled=True
        except DemandLimit as error:
            if error.dimension not in ('query', 'alternatives', 'depth'):raise
            note=type(error).__name__+': '+str(error)
            owner.query_pending[query.id]=(query.effect.origin, note)
            owner.query_history.append({'id':query.id, 'attempt':attempt, 'status':'incomplete', 'reason':note, **cost()})
            log_event(LOGGER, 'taint.query.incomplete', level=logging.WARNING, query_id=query.id,
                attempt=attempt, reason=note, **cost())
            known=set(sources.get(query.id, ()))|owner.partial_sources|owner.query_sources
            sources[query.id]=tuple(sorted(known, key=dependency_order))
            unknown=TaintDependency('unknown', 'Unresolved query '+query.id+': '+str(error), uncertain=True)
            sink=owner.active_sink
            if sink is None and query.kind=='call':
                rule=lookup(owner.demand.call_name(query.effect))
                if rule and rule.operation in ('copy', 'format_output', 'format_input', 'command', 'command_argv'):
                    sink=SinkRequirement(owner.base+owner.function.function_id.rva,
                        owner.base+query.effect.site.point.instruction_rva, rule.name,
                        'command' if rule.operation.startswith('command') else 'copy', (), (), query.effect.origin)
            if sink is not None:
                partials.setdefault(query.id, []).append(len(owner.completed_sinks))
                owner.completed_sinks.append(replace(sink, dependencies=sources[query.id]+(unknown,)))
            elif query.kind=='return':owner.completed_returns.extend(sources[query.id]+(unknown,))
            elif query.kind=='scalar_return':owner.completed_scalar_returns.extend(sources[query.id]+(unknown,))
            elif query.kind=='output':
                slot=query.payload
                owner.completed_outputs[slot]=tuple(dict.fromkeys(owner.completed_outputs.get(slot, ())+sources[query.id]+(unknown,)))
            elif query.kind=='global_output' and owner.active_global_output is not None:
                actual=tuple(sorted(owner.partial_sources|owner.query_sources, key=dependency_order))
                owner.add_global_output(replace(owner.active_global_output, dependencies=actual+(unknown,)), limited=True)
            if error.dimension=='query' and attempt<max_attempts:retries.append((query, attempt+1))
            handled=True
        finally:
            owner.clear_query_limits()
            if handled:
                owner.active_sink=None
                owner.active_global_output=None
                owner.partial_sources=set()
                owner.query_sources=set()
        if not todo and retries:
            todo.extend(sorted(retries, key=retry_cost))
            retries.clear()
    owner.current_query=None
