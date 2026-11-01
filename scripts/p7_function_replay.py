"""One-body replay with recorded portable summaries, separate from Gate A."""
import argparse
from dataclasses import asdict,replace
import hashlib
import inspect
import json
import os
from pathlib import Path
import sys
import tempfile
import time

TARGET=Path(__file__).resolve().parents[1]


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('source-root','summaries','acquisition','icall','binary','metadata','folder'):parser.add_argument('--'+name,type=Path,required=True)
    parser.add_argument('--functions',nargs='+',type=lambda value:int(value,0),required=True)
    parser.add_argument('--function-seconds',type=int,default=120)
    parser.add_argument('--query-sites',nargs='+',type=lambda value:int(value,0),
        help='Diagnostic only: run independent queries for these actual call sites')
    parser.add_argument('--inherited-sink-sites',nargs='+',type=lambda value:int(value,0),
        help='Diagnostic only: filter inherited sink queries, preserving other summary fields')
    parser.add_argument('--inspect-arguments',action='store_true')
    parser.add_argument('--inspect-only',action='store_true',
        help='Diagnostic only: snapshot selected call arguments and memory definitions without taint queries')
    parser.add_argument('--inspect-predecessors',action='store_true',
        help='Diagnostic only: snapshot r0-r2 at each selected call block predecessor')
    parser.add_argument('--inspect-argument-slots',nargs='+',type=int)
    parser.add_argument('--trace-sources',action='store_true')
    parser.add_argument('--trace-scalar-cost',action='store_true')
    parser.add_argument('--trace-query-cost',action='store_true')
    parser.add_argument('--trace-table',action='store_true',
        help='Diagnostic only: record bounded hsearch root reads and data-field checks')
    parser.add_argument('--trace-memory-origins',nargs='+',
        help='Bounded MemoryQueryPort/definition-frontier snapshots for these Load origin IDs')
    parser.add_argument('--inspect-selected-store-addresses',action='store_true',
        help='After a traced Load query, inspect only its selected Store address expressions')
    parser.add_argument('--inspect-selected-store-values',action='store_true',
        help='After a traced Load query, inspect only selected MustAlias Store values')
    parser.add_argument('--inspect-va-list',action='store_true',
        help='Diagnostic only: demand each local format_output_va_list transfer directly')
    parser.add_argument('--local-scalar-share-divisor',type=int,
        help='Diagnostic only: raise the independent scalar share for actual local sink calls')
    parser.add_argument('--local-call-full-share',action='store_true',
        help='Diagnostic only: use remaining function time and larger taint/scalar shares for local sink calls')
    parser.add_argument('--local-call-retry-full-share',action='store_true',
        help='Diagnostic only: enlarge local sink shares on retry after all first attempts')
    parser.add_argument('--refine-inherited',action='store_true',help='Diagnostic only: retry share-limited inherited sink queries with remaining budgets')
    parser.add_argument('--profile',action='store_true',help='Diagnostic CPU profile; profiling overhead affects wall-budget observations')
    parser.add_argument('--no-query-cache',action='store_true',help='Diagnostic P6 demand baseline without P7 cross-query caches')
    parser.add_argument('--inspect-sse',action='store_true',help='Include bounded SSE argument shape in diagnostic output')
    parser.add_argument('--inspect-path-guards',action='store_true',
        help='Diagnostic only: snapshot recognized guard operands at selected calls')
    args=parser.parse_args();source=args.source_root.resolve();source.relative_to(TARGET)
    if args.inspect_only and not args.inspect_arguments:parser.error('--inspect-only requires --inspect-arguments')
    sys.path.insert(0,str(source));sys.path.insert(1,str(TARGET/'scripts'))
    from p1_runtime import ProbeWriteGuard
    from p7_replay_codec import load_latest
    from emtaint.frontends.function_store import FunctionStore
    from emtaint.frontends.inputs import read_ida_cfg
    from emtaint.core import ContextId
    from emtaint.core.contracts import AnalysisScope,SemanticBudgets
    from emtaint.memory.image import ImageMemoryEngine
    from emtaint.compat.memory_runtime import MemoryRuntimePort
    from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
    from emtaint.analysis.dataflow.entry import legacy_entry
    from emtaint.analysis.dataflow.legacy_demand import DemandLimit
    from emtaint.memory.policies import BudgetExceeded
    from emtaint.analysis.taint.demand import LegacyTaintDemand,TaintProcedureSummary,dependency_order
    from emtaint.analysis.taint.evidence import summary_evidence,focused_snapshot
    from emtaint.results.memory_archive import archive_memory
    from emtaint.cli import source_manifest
    folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False);cache=folder/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);guard=ProbeWriteGuard([folder]).install();errors=[]
    try:
        sources=source_manifest(source)
        with (folder/'source-manifest.json').open('x') as stream:json.dump(sources,stream,indent=2)
        summaries,receipts,unfinished=load_latest(args.summaries.resolve());bank={}
        if args.inherited_sink_sites:
            summaries={address:replace(summary,sinks=tuple(sink for sink in summary.sinks
                if sink.site in args.inherited_sink_sites)) for address,summary in summaries.items()}
        for summary in summaries.values():
            for root,dependencies in summary.tables:
                if root.kind=='argument':continue
                incoming=tuple(replace(dep,recipes=(),unresolved_constraints=dep.unresolved_constraints or bool(dep.recipes)) for dep in dependencies if dep.kind=='source')
                bank[root]=tuple(sorted(set(bank.get(root,())+incoming),key=dependency_order))
        context={'summaries':{str(address):{'file':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()} for address,path in receipts.items()},
            'unfinished_receipts':unfinished,'table_roots':len(bank),'source_root':str(source),
            'query_sites':args.query_sites,'inherited_sink_sites':args.inherited_sink_sites,
            'inspect_arguments':args.inspect_arguments,'argv':sys.argv,'interpreter':sys.executable,'python':sys.version,
            'refine_inherited':args.refine_inherited,
            'query_cache':not args.no_query_cache,
            'runner_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'codec_sha256':hashlib.sha256((TARGET/'scripts/p7_replay_codec.py').read_bytes()).hexdigest(),
            'scope':'Recorded summary context; one-body diagnosis, not full-program fixed point or actual runtime invalidation'}
        with (folder/'context.json').open('x') as stream:json.dump(context,stream,indent=2)
        store=FunctionStore(args.acquisition,binary=args.binary);specs={spec.address:spec for spec in read_ida_cfg(args.metadata)}
        targets={int(site):values for rows in json.loads(args.icall.read_text()).values() for site,values in rows.items()}
        for address in args.functions:
            print('REPLAY '+hex(address),flush=True);started=time.monotonic()
            try:
                module,cfg,digest=store.load(address);scope=AnalysisScope(module.functions[0].function_id,ContextId(),'P7-recorded-context-replay',0,1,0)
                image_options={'initial_policy':'legacy-loader-snapshot'}
                if 'cache_resolutions' in inspect.signature(ImageMemoryEngine).parameters:image_options['cache_resolutions']=True
                engine=ImageMemoryEngine(scope,module.architecture,module.origin_map,store.segments,
                    SemanticBudgets(sse_nodes=200000,worklist_iterations=2000000),**image_options)
                port=(MemoryRuntimePort(engine,cache_alias_queries=True) if 'cache_alias_queries' in inspect.signature(MemoryRuntimePort).parameters
                    else MemoryRuntimePort(engine))
                tick=time.monotonic()
                def deadline():
                    if time.monotonic()-tick>args.function_seconds:raise DemandLimit('Replay function wall budget',dimension='time')
                port.validate_current=deadline
                demand_options={'names':{call.instruction-store.base:call.target for call in specs[address].calls if type(call.target) is str},
                    'summaries':summaries,'targets':targets,'image_base':store.base,'tables':dict(bank)}
                if args.no_query_cache:demand_options['cache_queries']=False
                if 'function_deadline' in inspect.signature(LegacyTaintDemand).parameters:demand_options['function_deadline']=tick+args.function_seconds
                demand=LegacyTaintDemand(module.functions[0],port,cfg,legacy_entry(CIRAccurateDataFlow(port)),**demand_options)
                query_arguments=[];query_predecessors=[];query_path_guards=[];va_list_probe=[]
                table_trace=[]
                if args.trace_table:
                    original_table_read=demand.table_state.read
                    original_data_check=demand.table_state.data_field_query
                    def traced_table_read(root,call):
                        result=original_table_read(root,call)
                        if len(table_trace)<64:table_trace.append({'kind':'read','origin':call.origin,'root':str(root),
                            'dependencies':[(dep.kind,str(dep.value),dep.constraints,len(dep.recipes)) for dep in result]})
                        return result
                    def traced_data_check(reference,call):
                        result=original_data_check(reference,call)
                        if len(table_trace)<64:
                            def shape(item,depth=0):
                                node=engine.dag.nodes[item]
                                if depth>=5:return (node.op.value,'depth')
                                return (node.op.value,node.value if node.op.value in ('constant','symbol','unknown') else None,
                                    item in demand.demand.loads,tuple(shape(child,depth+1) for child in node.operands[:2]))
                            table_trace.append({'kind':'data-field','origin':call.origin,
                                'reference':str(reference),'matched':result,'shape':shape(reference)})
                        return result
                    demand.table_state.read=traced_table_read
                    demand.table_state.data_field_query=traced_data_check
                profiler=None
                if args.profile:
                    import cProfile
                    profiler=cProfile.Profile();profiler.enable()
                source_progress=[]
                query_cost=[]
                memory_origin_trace=[];memory_store_values=[]
                memory_store_addresses=[]
                scalar_cost={}
                share_limited={};refinement=[]
                if args.trace_memory_origins:
                    selected=set(args.trace_memory_origins);active=[]
                    scalar=demand.demand;frontiers=scalar.frontiers
                    original_memory=scalar.memory_definitions
                    original_select=frontiers.select
                    original_unknown=frontiers.unknown_query
                    def location_record(location):
                        return {'object_id':str(location.object_id),'offset_lower':location.offset_lower,
                            'offset_upper':location.offset_upper,'width_bits':location.width_bits,
                            'origin':location.origin,'memory_version':str(scalar.initial.memory)}
                    def traced_select(block,index,location,depth):
                        result=original_select(block,index,location,depth)
                        if active and active[-1] in selected and len(memory_origin_trace)<32:
                            stores,initial_possible,cacheable=result
                            memory_origin_trace.append({'stage':'select','load_origin':active[-1],
                                'block_rva':block.rva,'cutoff':index,'location':location_record(location),
                                'stores':[{'origin':effect.origin,'location':location_record(store),
                                    'alias':alias.value} for effect,store,alias in stores[:32]],
                                'store_count':len(stores),'initial_possible':initial_possible,
                                'cacheable':cacheable})
                        return result
                    def traced_unknown(block,index,location,load,depth):
                        result=original_unknown(block,index,location,load,depth)
                        if load.origin in selected and len(memory_origin_trace)<32:
                            memory_origin_trace.append({'stage':'unknown_shortcut','load_origin':load.origin,
                                'block_rva':block.rva,'cutoff':index,'location':location_record(location),
                                'used':result is not None,
                                'alternatives':[] if result is None else [str(value) for value in result[0]]})
                        return result
                    def traced_memory(block,index,location,load,seen,depth):
                        active.append(load.origin)
                        try:
                            result=original_memory(block,index,location,load,seen,depth)
                            if load.origin in selected and len(memory_origin_trace)<32:
                                memory_origin_trace.append({'stage':'result','load_origin':load.origin,
                                    'block_rva':block.rva,'cutoff':index,'location':location_record(location),
                                    'alternatives':[{'id':str(value),'op':engine.dag.nodes[value].op.value,
                                        'concrete':port.concrete(value)}
                                        for value in result[0]],'killed':result[1]})
                            return result
                        finally:active.pop()
                    scalar.memory_definitions=traced_memory
                    frontiers.select=traced_select
                    frontiers.unknown_query=traced_unknown
                if args.refine_inherited:
                    original_bind_sink=demand.bind_sink
                    def record_limited(sink,call,block,index):
                        try:return original_bind_sink(sink,call,block,index)
                        except DemandLimit as error:
                            if error.dimension=='query':share_limited[sink,call.origin]=(sink,call,block,index)
                            raise
                    demand.bind_sink=record_limited
                if args.trace_scalar_cost:
                    original_tick=demand.demand.tick
                    def traced_tick(depth):
                        frame=sys._getframe(1);caller=frame.f_code.co_name
                        if caller=='register':
                            caller+=':'+str(frame.f_locals.get('name','?'))
                        location=frame.f_locals.get('loc',frame.f_locals.get('location'))
                        if location is not None and hasattr(location,'object_id'):
                            caller+=':'+('unknown' if location.object_id is None else location.object_id.kind.value)
                            caller+=':range' if location.offset_lower is None else ':offset'
                        scalar_cost[caller]=scalar_cost.get(caller,0)+1
                        return original_tick(depth)
                    demand.demand.tick=traced_tick
                if args.trace_sources:
                    original_source=demand.source;original_import=demand.import_source
                    def progress(dependency):
                        source_progress.append({'source':dependency.value,'taint_steps':demand.steps,
                            'scalar_steps':demand.demand.steps,'query_origin':demand.frontier,
                            'sink_site':None if demand.active_sink is None else demand.active_sink.site})
                    def traced_source(*values,**keywords):
                        dependency=original_source(*values,**keywords);progress(dependency);return dependency
                    def traced_import(dependency,*values,**keywords):
                        progress(dependency);return original_import(dependency,*values,**keywords)
                    demand.source=traced_source;demand.import_source=traced_import
                if args.trace_query_cost:
                    original_execute=demand.execute_query
                    def traced_query(query):
                        before=(demand.steps,demand.demand.steps,engine.accounting.counts['worklist_iterations'],time.monotonic())
                        status='completed'
                        try:return original_execute(query)
                        except BaseException as error:
                            status=type(error).__name__+': '+str(error)
                            raise
                        finally:
                            query_cost.append({'id':query.id,'kind':query.kind,'origin':query.effect.origin,'status':status,
                                'taint_steps':demand.steps-before[0],'scalar_steps':demand.demand.steps-before[1],
                                'memory_work':engine.accounting.counts['worklist_iterations']-before[2],
                                'seconds':time.monotonic()-before[3]})
                    demand.execute_query=traced_query
                if args.local_scalar_share_divisor or args.local_call_full_share or args.local_call_retry_full_share:
                    from emtaint.procedures.legacy import lookup
                    original_begin=demand.begin_query;attempts={}
                    def boosted_begin(query=None):
                        original_begin(query)
                        if query is not None and query.kind=='call':
                            attempts[query.id]=attempts.get(query.id,0)+1
                            rule=lookup(demand.demand.call_name(query.effect))
                            boost=bool(args.local_call_full_share or args.local_call_retry_full_share and attempts[query.id]>1)
                            if rule and rule.operation in ('copy','format_output','format_input','command','command_argv') and (boost or args.local_scalar_share_divisor):
                                scalar=demand.demand
                                scalar.query_scalar_limit=max(scalar.query_scalar_limit,
                                    scalar.steps+scalar.budget.steps//(4 if boost else args.local_scalar_share_divisor))
                                if boost:
                                    demand.query_step_limit=max(demand.query_step_limit,demand.steps+demand.max_steps//8)
                                    demand.query_clock_limit=demand.function_deadline
                    demand.begin_query=boosted_begin
                if args.query_sites:
                    from emtaint.ir.canonical import CallEffect
                    schedule=demand.query_schedule()
                    demand.query_schedule=lambda:tuple((block,tuple((i,effect) for i,effect in effects
                        if isinstance(effect,CallEffect) and store.base+effect.site.point.instruction_rva in args.query_sites))
                        for block,effects in schedule)
                    for _,_,call in demand.calls.values():
                        if store.base+call.site.point.instruction_rva not in args.query_sites:continue
                        if args.inspect_path_guards:
                            demand.path_guards(call)
                            for origin,relation,bound,left in demand.path_guard_operands.get(call.origin,()):
                                try:
                                    values=demand.demand.value(left)
                                    roots=[]
                                    for value in values[:16]:
                                        node=engine.dag.nodes[value]
                                        while node.op.value=='copy':
                                            value=node.operands[0];node=engine.dag.nodes[value]
                                        roots.append({'id':value.key,'op':node.op.value,'value':node.value,
                                            'bits':node.type.bits,'origin':node.origin})
                                    query_path_guards.append({'call':call.origin,'branch':origin,
                                        'relation':relation,'bound':bound,'roots':roots,
                                        'truncated':len(values)>16})
                                except (DemandLimit,BudgetExceeded,RecursionError) as error:
                                    query_path_guards.append({'call':call.origin,'branch':origin,
                                        'relation':relation,'bound':bound,'error':type(error).__name__+': '+str(error)})
                        if not args.inspect_arguments:continue
                        for slot in (args.inspect_argument_slots if args.inspect_argument_slots is not None else range(8)):
                            for reference in demand.argument(call,slot):
                                node=engine.dag.nodes[reference];binding=demand.demand.address_binding(reference)
                                try:alternatives,open_tail,_=port.candidates(reference,limit=64)
                                except BudgetExceeded:alternatives,open_tail=(),True
                                leaves=[];seen=set();stack=[reference]
                                while stack and len(seen)<128:
                                    item=stack.pop()
                                    if item in seen:continue
                                    seen.add(item);child=engine.dag.nodes[item]
                                    if child.operands:stack.extend(child.operands)
                                    else:leaves.append((child.op.value,str(child.value)[:80],child.origin))
                                shape=None
                                if args.inspect_sse:
                                    def outline(item,depth=0):
                                        child=engine.dag.nodes[item]
                                        if depth>=8:return ('depth',child.op.value,child.origin)
                                        return (child.op.value,child.value if child.op.value in ('constant','symbol','unknown') else None,
                                            child.origin,tuple(outline(x,depth+1) for x in child.operands[:3]))
                                    shape=outline(reference)
                                row={'site':store.base+call.site.point.instruction_rva,'slot':slot,
                                    'value':str(node),'binding':str(binding),'runtime_constant':port.guard_concrete(reference),
                                    'candidate_values':alternatives,'candidate_open_tail':open_tail,
                                    'leaves':sorted(set(leaves)),'leaf_scan_truncated':bool(stack)}
                                if args.inspect_sse:row['sse_shape']=shape
                                query_arguments.append(row)
                        if args.inspect_predecessors:
                            call_block,_,_=demand.calls[call.origin]
                            for predecessor in demand.demand.predecessors[call_block]:
                                for register in ('r0','r1','r2'):
                                    row={'site':store.base+call.site.point.instruction_rva,
                                        'block_rva':call_block.rva,'predecessor_rva':predecessor.rva,
                                        'register':register,'alternatives':[]}
                                    try:
                                        values=demand.demand.register(predecessor,
                                            len(demand.demand.blocks[predecessor].effects),register,32,0)
                                        for value in values[:32]:
                                            candidates,open_tail,_=port.candidates(value,limit=16)
                                            row['alternatives'].append({'concrete':port.guard_concrete(value),
                                                'candidates':list(candidates),'open_tail':open_tail})
                                    except (DemandLimit,BudgetExceeded,RecursionError) as error:
                                        row['error']=type(error).__name__+': '+str(error)
                                    query_predecessors.append(row)
                if args.inspect_va_list:
                    from emtaint.procedures.legacy import lookup
                    for origin,(block,index,call) in demand.calls.items():
                        rule=lookup(demand.demand.call_name(call))
                        if rule is None or rule.operation!='format_output_va_list':continue
                        try:
                            dependencies=demand.va_list_dependencies(call,block,index,rule)
                            va_list_probe.append({'origin':origin,
                                'dependencies':[(dep.kind,str(dep.value),dep.constraints,
                                    dep.uncertain,dep.unresolved_constraints) for dep in dependencies]})
                        except (DemandLimit,BudgetExceeded,RecursionError) as error:
                            va_list_probe.append({'origin':origin,
                                'error':type(error).__name__+': '+str(error)})
                summary=TaintProcedureSummary(address) if args.inspect_only else demand.analyze()
                if args.refine_inherited:
                    from emtaint.analysis.taint.demand import sink_order,TaintDependency
                    pending=list(summary.pending);tasks=list(share_limited.values())
                    for number,(sink,call,block,index) in enumerate(tasks):
                        demand.query_step_limit=None;demand.queries_remaining=len(tasks)-number;demand.begin_query()
                        demand.active_sink=sink;demand.partial_sources=set();demand.frontier=call.origin
                        try:
                            demand.add_sink(demand.bind_sink(sink,call,block,index))
                            refinement.append({'site':sink.site,'call':store.base+call.site.point.instruction_rva,'status':'query_returned'})
                        except (DemandLimit,BudgetExceeded) as error:
                            refinement.append({'site':sink.site,'call':store.base+call.site.point.instruction_rva,
                                'status':'incomplete','reason':str(error),'dimension':getattr(error,'dimension',None)})
                            demand.completed_sinks.append(replace(demand.active_sink,dependencies=tuple(sorted(demand.partial_sources,key=dependency_order))+
                                (TaintDependency('unknown','Refinement frontier: '+str(error),uncertain=True),)))
                            if getattr(error,'dimension',None) not in ('query','alternatives','depth'):
                                pending.append(('Diagnostic refinement stopped',type(error).__name__+': '+str(error)));break
                        finally:demand.active_sink=None;demand.partial_sources=set()
                    summary=replace(summary,sinks=tuple(sorted(set(demand.completed_sinks),key=sink_order)),
                        pending=tuple(pending)+('Diagnostic refinement retains first-pass pending history; not a production completeness claim',))
                if profiler:
                    profiler.disable();profiler.dump_stats(str(folder/(hex(address)+'.pstats')))
                encoded=summary_evidence(summary,demand.covered_sources) if hasattr(demand,'covered_sources') else summary_evidence(summary)
                memory_origin_arenas={'paths':[],'reads':[]}
                if args.trace_memory_origins:
                    selected=set(args.trace_memory_origins)
                    for path in engine.paths.values():
                        if path.origin not in selected or len(memory_origin_arenas['paths'])>=32:continue
                        graph=demand.demand.apg._intern.get((path.root,path.segments,port.point(path.origin)))
                        memory_origin_arenas['paths'].append({'origin':path.origin,'path_id':str(path.id),
                            'root':str(path.root),'segments':[str(segment) for segment in path.segments],
                            'graph_id':str(graph),'assessment':str(path.assessment)})
                    for read in engine.reads:
                        if read.origin not in selected or len(memory_origin_arenas['reads'])>=32:continue
                        loc=engine.locations[read.location]
                        memory_origin_arenas['reads'].append({'origin':read.origin,'state':str(read.state),
                            'location':str(read.location),'root':str(loc.object_id),
                            'offset_lower':loc.offset_lower,'offset_upper':loc.offset_upper,
                            'result':str(read.result),'guard':str(read.guard)})
                if args.inspect_selected_store_addresses and memory_origin_trace:
                    from emtaint.ir.canonical import StoreEffect,Compute,ReadRegister
                    def address_chain(operand,seen=frozenset(),depth=0):
                        if depth>=10 or not hasattr(operand,'id') or operand.id in seen:
                            return str(operand)[:90]
                        definition=demand.demand.defs.get(operand.id)
                        if definition is None:return str(operand)[:90]
                        effect=definition[2]
                        if isinstance(effect,Compute):
                            return [effect.op.value,*[address_chain(arg,seen|{operand.id},depth+1) for arg in effect.args]]
                        if isinstance(effect,ReadRegister):return ['read-register',effect.source.register]
                        return [type(effect).__name__,str(operand)[:90]]
                    selected_stores={row['origin'] for item in memory_origin_trace
                        if item['stage']=='select' for row in item['stores']}
                    for block in demand.function.blocks:
                        for effect in block.effects:
                            if not isinstance(effect,StoreEffect) or effect.origin not in selected_stores:continue
                            row={'origin':effect.origin,'block_rva':block.id.rva,
                                'width_bits':effect.width_bits,'local_address':str(demand.demand.local_address(effect.address)),
                                'exact_stack_address':str(demand.demand.exact_stack_address(effect.address)),
                                'address_chain':address_chain(effect.address),
                                'values':[]}
                            try:
                                for value in demand.demand.value(effect.address):
                                    alternatives,open_tail,_=port.candidates(value,limit=16)
                                    row['values'].append({'id':str(value),'concrete':port.concrete(value),
                                        'candidates':list(alternatives),'open_tail':open_tail})
                            except (DemandLimit,BudgetExceeded,RecursionError) as error:
                                row['error']=type(error).__name__+': '+str(error)
                            memory_store_addresses.append(row)
                if args.inspect_selected_store_values and memory_origin_trace:
                    from emtaint.ir.canonical import StoreEffect
                    selected={row['origin'] for item in memory_origin_trace if item['stage']=='select'
                        for row in item['stores'] if row.get('alias')=='must_alias'}
                    for block in demand.function.blocks:
                        for effect in block.effects:
                            if not isinstance(effect,StoreEffect) or effect.origin not in selected:continue
                            row={'origin':effect.origin,'block_rva':block.id.rva,'values':[]}
                            try:
                                for value in demand.demand.value(effect.value)[:32]:
                                    candidates,open_tail,_=port.candidates(value,limit=32)
                                    row['values'].append({'concrete':port.guard_concrete(value),
                                        'candidates':list(candidates),'open_tail':open_tail,
                                        'op':engine.dag.nodes[value].op.value})
                            except (DemandLimit,BudgetExceeded,RecursionError) as error:
                                row['error']=type(error).__name__+': '+str(error)
                            memory_store_values.append(row)
                record={**encoded,'source_facts':[asdict(fact) for fact in engine.facts],
                    'metrics':port.metrics(),'cir_sha256':digest,'wall_seconds':time.monotonic()-started,
                    'query_arguments':query_arguments,'query_predecessors':query_predecessors,
                    'query_path_guards':query_path_guards,
                    'source_progress':source_progress,
                    'table_trace':table_trace,
                    'inherited_refinement':refinement,
                    'query_history':getattr(demand,'query_history',[]),'query_cost':query_cost,
                    'alternative_overflows':getattr(demand,'alternative_overflows',[]),
                    'local_recoveries':getattr(demand,'local_recoveries',[]),
                    'va_list_diagnostics':getattr(demand,'va_list_diagnostics',[]),
                    'va_list_probe':va_list_probe,
                    'memory_origin_trace':memory_origin_trace,
                    'memory_origin_arenas':memory_origin_arenas,
                    'memory_store_addresses':memory_store_addresses,
                    'memory_store_values':memory_store_values,
                    'pending_query_ids':list(getattr(demand,'query_pending',{})),
                    'argument_preparations':getattr(demand,'argument_preparations',[]),
                    'taint_steps':demand.steps,'scalar_steps':demand.demand.steps,
                    'scalar_cost':scalar_cost,'scalar_diagnostics':demand.demand.notes,
                    'definition_frontier_cache':None if not hasattr(demand.demand,'frontiers') else {
                        'hits':demand.demand.frontiers.hits,'misses':demand.demand.frontiers.misses,
                        'entries':len(demand.demand.frontiers.cache)},
                    'recurrence_cache':{'hits':getattr(demand.demand,'recurrence_cache_hits',0),
                        'entries':len(getattr(demand.demand,'recurrence_cache',{}))},
                    'unknown_frontiers':sorted(demand.unknown_evidence)}
                if engine.facts:archive_memory(focused_snapshot(engine.snapshot()),folder/(hex(address)+'-source-memory'))
            except Exception as error:
                record={'error':type(error).__name__+': '+str(error),'wall_seconds':time.monotonic()-started};errors.append(record)
            with (folder/(hex(address)+'.json')).open('x',encoding='utf8') as stream:json.dump(record,stream,indent=2,default=str)
            print('DONE '+hex(address)+' '+str(round(record['wall_seconds'],3)),flush=True)
        report={'errors':errors,'source_unchanged_during_run':sources==source_manifest(source),'violations':guard.violations,
            'scope':'Single-function controlled replay; no Gate A claim'}
        with (folder/'replay-report.json').open('x') as stream:json.dump(report,stream,indent=2)
        return 0 if not errors and not guard.violations and report['source_unchanged_during_run'] else 1
    finally:guard.restore()


if __name__=='__main__':raise SystemExit(main())
