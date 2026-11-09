"""Session-owned interprocedural P7 summaries over actual acquired CIR."""

from __future__ import annotations

import argparse
from dataclasses import asdict, replace
import hashlib
import json
import logging
from pathlib import Path
import time
import uuid
from types import MappingProxyType
from typing import TYPE_CHECKING
from emtaint.core import ContextId, FunctionId
from emtaint.core.contracts import AnalysisScope, SemanticBudgets
from emtaint.graph import CallGraph, CallEdge, TargetKind
from emtaint.analysis.framework.runtime import AnalysisRuntime
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.taint.demand import LegacyTaintDemand, TaintProcedureSummary, dependency_order
from emtaint.analysis.taint.table_dependencies import TableReadIndex
from emtaint.analysis.taint.summary_join import SummaryAccumulator, semantic_equal
from emtaint.analysis.bugfinder.legacy_policy import WeakEvidence, LegacySecurityPolicy
from emtaint.analysis.bugfinder.candidate_evidence import (candidate_key, requirement_references,
    source_fact_references, merge_fact_references, CANDIDATE_REFS_FORMAT)
from emtaint.memory.image import ImageMemoryEngine
from emtaint.memory.policies import BudgetExceeded
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.frontends.inputs import read_ida_cfg
from emtaint.orchestration.legacy_cir_search import callee_first
from emtaint.procedures.legacy_policy import excluded_functions
from emtaint.analysis.taint.evidence import summary_evidence, EvidenceEncoder, focused_snapshot
from emtaint.procedures.legacy import legacy_copy_weak_kind, uniform_copy_length_constraints
from emtaint.results.memory_archive import archive_memory
from emtaint.debugging import function_address_fields, log_event


LOGGER = logging.getLogger(__name__)

if TYPE_CHECKING:
    from emtaint.frontends.function_store import FunctionStore


def summary_receipt_paths(
    receipt: Path,
    raw_summary: TaintProcedureSummary,
    summary: TaintProcedureSummary,
) -> tuple[Path, Path]:
    """Return lossless raw/final evidence paths without identical duplication."""
    result=receipt.with_name(receipt.name+'-result.json')
    raw=result if raw_summary==summary else receipt.with_name(receipt.name+'-raw-summary.json')
    return raw, result


def run_taint(
    args: argparse.Namespace, store: FunctionStore, folder: Path
) -> dict[str, object]:
    """Run bounded interprocedural taint fixed points over an acquired program.

    The store type is imported only for static checking so the existing CLI SCC
    does not gain another runtime import edge.
    """

    from emtaint.cli import write
    started=time.monotonic()
    attempt=uuid.uuid4().hex[:8]
    phase=folder/('taint-'+attempt)
    phase.mkdir(exist_ok=False)
    previous=json.loads((folder/'icall.json').read_text(encoding='utf8'))
    if previous['binary_sha256']!=store.report['binary_sha256'] or previous['status']!='candidate_fixed_point':raise ValueError('A matching fixed-point -i result is required')
    if previous.get('plt_sha256', store.plt_sha256)!=store.plt_sha256:raise ValueError('The -i/-t PLT identity differs')
    specs=read_ida_cfg(Path(args.ida_data)/'httpd_cfg.json')
    by_address={s.address:s for s in specs}
    index=store.program_index(specs)
    runtime=AnalysisRuntime(index.program)
    targets=json.loads((folder/'icall-targets.json').read_text(encoding='utf8'))
    site_targets={int(site):values for calls in targets.values() for site, values in calls.items()}
    graph=index.cg
    edges=set(graph.edges)
    for site in index.program.callsites:
        address=None if site.id.point.instruction_rva is None else site.id.point.instruction_rva+store.base
        for value in site_targets.get(address, ()):
            target=index.program.function_at(value)
            if target is not None:edges.add(CallEdge(site.id, target.id, TargetKind.MAY, 'P7 preceding fresh -i candidate'))
    runtime.session.replace_cg(CallGraph(graph.nodes, frozenset(edges), graph.status, graph.reason))
    for cfg in index.cfgs:runtime.session.replace_cfg(cfg)
    excluded=excluded_functions(store.report['binary_sha256'])
    selected=getattr(args, 'taint_functions', None)
    allowed=set(graph.nodes) if selected is None else {f for f in graph.nodes if f.rva+store.base in selected}
    if selected is not None and {f.rva+store.base for f in allowed}!=set(selected):raise ValueError('Diagnostic selection includes unknown functions')
    selected_excluded=excluded&{f.rva+store.base for f in allowed}
    summaries={address:TaintProcedureSummary(address, pending=('Original FastSearch ignore_function coverage exclusion; memory effects unknown',)) for address in selected_excluded}
    last={}
    invocations=[]
    todo={f for f in allowed if f.rva+store.base not in excluded}
    rounds=0
    table_bank={}
    table_readers=TableReadIndex()
    table_version=0
    table_events=[]
    accumulated=SummaryAccumulator()
    summary_receipts={}
    source_evidence_index={}
    caller_by_site={site.id.point.instruction_rva+store.base:site.id.function.rva+store.base
        for site in index.program.callsites if site.id.point.instruction_rva is not None}
    log_event(LOGGER, 'taint.started', level=logging.INFO, attempt=attempt, functions=len(allowed),
        initial_worklist=len(todo), coverage='full-program' if selected is None else 'diagnostic-subset',
        function_seconds=args.function_seconds, round_budget=args.taint_rounds)
    while todo and rounds<args.taint_rounds:
        rounds+=1
        changed=set()
        log_event(LOGGER, 'taint.round.started', level=logging.INFO, round=rounds, worklist=len(todo),
            pending=len(runtime.pending), table_version=table_version)
        runtime.pending.difference_update(todo)
        for fid in callee_first(todo, runtime.session.cg):
            receipt=phase/('round-'+str(rounds).zfill(3)+'-function-'+hex(fid.rva+store.base))
            write(receipt.with_name(receipt.name+'-start.json'), {'function':fid.rva+store.base, 'round':rounds, 'status':'started'})
            address=fid.rva+store.base
            module, cfg, digest=store.load(address)
            debug_provenance = store.load_debug_provenance(address, module)
            log_event(LOGGER, 'taint.function.started',
                **function_address_fields(fid.rva, store.base, legacy_field='va'), round=rounds,
                cir_sha256=digest, summary_inputs=len(summaries))
            # Native/IDA edge refinement is explicit and versioned.
            runtime.replace_cfg(cfg)
            context=ContextId()
            scope=AnalysisScope.from_session(runtime.session, fid, context)
            engine=ImageMemoryEngine(scope, module.architecture, module.origin_map, store.segments,
                SemanticBudgets(sse_nodes=200000, worklist_iterations=2000000), initial_policy='legacy-loader-snapshot', cache_resolutions=True)
            engine.debug_provenance = debug_provenance
            # Presentation-only mapping; core analysis identities remain RVAs.
            if getattr(args, 'debug_ida_image_base', None) is not None or getattr(args, 'debug_runtime_base', None) is not None:
                from emtaint.analysis_debugging import AddressTranslator
                engine.debug_address_translator = AddressTranslator(
                    module.binary_sha256,
                    ida_image_base=getattr(args, 'debug_ida_image_base', None),
                    runtime_base=getattr(args, 'debug_runtime_base', None),
                    address_bits=module.architecture.address_bits,
                )
            port=MemoryRuntimePort(engine, cache_alias_queries=True)
            runtime.bind_port(port, fid, context)
            tick=time.monotonic()
            validate=port.validate_current
            def validate_deadline():
                validate()
                if time.monotonic()-tick>args.function_seconds:raise DemandLimit('Function wall deadline; unresolved frontier remains')
            port.validate_current=validate_deadline
            names={c.instruction-store.base:c.target for c in by_address[address].calls if type(c.target) is str}
            demand=None
            trace_recorder=None
            try:
                demand=LegacyTaintDemand(module.functions[0], port, cfg, legacy_entry(CIRAccurateDataFlow(port)),
                    names=names, summaries=summaries, targets=site_targets, image_base=store.base, tables=MappingProxyType(dict(table_bank)),
                    function_deadline=tick+args.function_seconds)
                if getattr(args, 'debug_trace', False):
                    from emtaint.analysis_debugging import AnalysisTraceRecorder
                    trace_recorder = AnalysisTraceRecorder(
                        enabled=True, max_events=args.debug_trace_max_events
                    )
                    demand.demand.enable_debug_trace(trace_recorder)
                summary=demand.analyze()
            except (BudgetExceeded, DemandLimit, RecursionError) as error:
                log_event(LOGGER, 'taint.function.limited', level=logging.WARNING, error_type=type(error).__name__,
                    error_message=str(error),
                    **function_address_fields(fid.rva, store.base, legacy_field='va'), round=rounds)
                summary=demand.partial_summary(error) if demand else TaintProcedureSummary(address, pending=(('constructor', type(error).__name__+': '+str(error)),))
            trace_path = None
            if trace_recorder is not None:
                trace_path = receipt.with_name(receipt.name + '-trace.jsonl')
                trace_recorder.export_jsonl(trace_path)
            raw_summary=summary
            callees=sorted({callee for _, _, call in demand.calls.values()
                for callee in demand.call_functions(call)}) if demand else []
            callee_revision=hashlib.sha256(repr(tuple((callee, summaries.get(callee))
                for callee in callees)).encode('utf8')).hexdigest()
            identity=(digest, store.plt_sha256, previous['binary_sha256'], args.function_seconds,
                scope.cg_version, runtime.epochs[fid],
                None if demand is None else demand.demand.initial.memory.key,
                callee_revision)
            summary=accumulated.update(identity, raw_summary, context=context)
            raw_path, result_path=summary_receipt_paths(receipt, raw_summary, summary)
            if raw_path!=result_path:
                write(raw_path, summary_evidence(raw_summary, demand.covered_sources if demand else ()))
            if not semantic_equal(summaries.get(address), summary):changed.add(fid)
            summaries[address]=summary
            last[address]={'summary':summary, 'metrics':port.metrics(), 'steps':getattr(demand, 'steps', 0),
                           'debug_trace':None if trace_recorder is None else {
                               'path':str(trace_path),
                               'events':len(trace_recorder.events()),
                               'dropped':trace_recorder.dropped,
                           },
                           'source_facts':[asdict(f) for f in engine.facts], 'transformation':store.transformations.get(address),
                           'unknown_frontiers':sorted(demand.unknown_evidence) if demand else [],
                           'cir_sha256':digest, 'raw_summary':str(raw_path),
                           'retained_evidence_receipts':list(summary_receipts.get(address, ())) if summary!=raw_summary else [],
                           'table_source_version':table_version,
                           'query_history':getattr(demand, 'query_history', []),
                           'pending_query_ids':list(getattr(demand, 'query_pending', {})),
                           'argument_preparations':getattr(demand, 'argument_preparations', []),
                           'scalar_diagnostics':sorted(set(demand.demand.notes)) if demand else [],
                           'wall_seconds':time.monotonic()-tick}
            invocations.append({'function':address, 'round':rounds, 'pending':len(summary.pending),
                'sinks':len(summary.sinks), 'source_facts':len(engine.facts), 'steps':getattr(demand, 'steps', 0), 'wall_seconds':time.monotonic()-tick})
            log_event(LOGGER, 'taint.function.completed',
                **function_address_fields(fid.rva, store.base, legacy_field='va'), round=rounds,
                changed=fid in changed, pending=len(summary.pending), sinks=len(summary.sinks),
                source_facts=len(engine.facts), queries=len(getattr(demand, 'query_history', ())),
                taint_steps=getattr(demand, 'steps', 0), memory_metrics=last[address]['metrics'],
                wall_seconds=time.monotonic()-tick)
            if engine.facts:
                archive_started=time.monotonic()
                archive_folder=receipt.with_name(receipt.name+'-source-memory')
                archive=archive_memory(focused_snapshot(engine.snapshot()), archive_folder)
                last[address]['source_memory_evidence']={'directory':str(archive_folder), 'scope':'Reference-closed source slice; full CIR is the replay input',
                    'manifest_sha256':hashlib.sha256((archive_folder/'manifest.json').read_bytes()).hexdigest(),
                    'records':{name:entry['records'] for name, entry in archive['groups'].items()},
                    'wall_seconds':time.monotonic()-archive_started}
                bindings=tuple(demand.source_bindings.values())+tuple(demand.imported_bindings.values()) if demand else ()
                actual_facts=set(engine.facts)
                source_bindings=[]
                for binding in bindings:
                    if binding.fact not in actual_facts:raise ValueError('Source binding does not belong to its archived memory evidence')
                    evidence={'source_site':binding.source_site, 'fact_id':binding.fact.id, 'origin':binding.fact.origin,
                        'program_site':store.base+port.point(binding.fact.origin).instruction_rva,
                        'function':address, 'round':rounds, 'receipt':str(result_path),
                        'archive':str(archive_folder), 'manifest_sha256':last[address]['source_memory_evidence']['manifest_sha256'],
                        'binding':asdict(binding), 'scope':'Actual may-source fact; does not by itself prove the full caller-to-sink path'}
                    source_bindings.append(evidence)
                    source_evidence_index.setdefault(binding.source_site, []).append(evidence)
                last[address]['source_bindings']=source_bindings
            write(result_path, {**last[address],
                **summary_evidence(summary, demand.covered_sources if demand else ()), 'invocation':invocations[-1]})
            summary_receipts.setdefault(address, []).append(str(result_path))
            runtime.put('summary', fid, context, 'taint', ('detached-taint-summary', hashlib.sha256(repr(summary).encode()).hexdigest()))
            runtime.pending.discard(fid)
            if demand:
                table_readers.replace(fid, demand.table_state.reads, demand.table_state.broad_reads)
            for root, dependencies in summary.tables:
                if root.kind=='argument':continue
                if root.binary!=store.report['binary_sha256']:raise ValueError('Foreign-binary hash table summary')
                sources=tuple(replace(dep, recipes=(), unresolved_constraints=dep.unresolved_constraints or bool(dep.recipes))
                    if dep.kind=='source' else dep for dep in dependencies if dep.kind in ('source', 'unknown'))
                previous_sources=table_bank.get(root, ())
                joined=tuple(sorted(dict.fromkeys(previous_sources+sources), key=dependency_order))
                if joined!=previous_sources:
                    table_bank[root]=joined
                    table_version+=1
                    readers=table_readers.affected(root)
                    affected=runtime.invalidate_dependencies(readers, 'P7 hsearch source-state version '+str(table_version)) if readers else frozenset()
                    table_events.append({'version':table_version, 'writer':address, 'table':asdict(root), 'source_sites':sorted({dep.value for dep in joined if dep.kind=='source'}),
                        'invalidated':[value.rva+store.base for value in sorted(affected, key=lambda f:f.rva)]})
                    log_event(LOGGER, 'taint.table.updated', writer=hex(address), version=table_version,
                        sources=len(joined), invalidated=len(affected))
            if len(invocations)%25==0:print('TAINT_FUNCTIONS='+str(len(invocations))+' round='+str(rounds), flush=True)
        affected=runtime.invalidate_dependencies(changed, 'P7 taint procedure summary changed')
        # A changed logical summary invalidates dependent results. Ports are
        # reconstructed on the next pass; portable summaries contain no IDs.
        todo={f for f in (set(affected)|set(runtime.pending))&allowed if f.rva+store.base not in excluded}
        log_event(LOGGER, 'taint.round.completed', level=logging.INFO, round=rounds, changed=len(changed),
            invalidated=len(affected), next_worklist=len(todo), invocations=len(invocations))
    sources={dep.value for summary in summaries.values() for sink in summary.sinks for dep in sink.dependencies if dep.kind=='source'}
    max_length=LegacySecurityPolicy.guess_max_length(bound for summary in summaries.values() for sink in summary.sinks
        for dep in sink.dependencies if dep.kind=='source' for bound in dep.constraints)
    handles={}
    for summary in summaries.values():
        for sink in summary.sinks:
            for dep in sink.dependencies:
                if dep.kind=='source':handles.setdefault(dep.value, set()).update(kind for kind, value in dep.handles)
    fake_sources={source for source, kinds in handles.items() if 'file' in kinds and 'socket' not in kinds}
    source_index_path=phase/'source-evidence-index.json'
    write(source_index_path, source_evidence_index)
    source_index_sha=hashlib.sha256(source_index_path.read_bytes()).hexdigest()
    policy=LegacySecurityPolicy(max_length=max_length, fake_sources=fake_sources)
    candidates={}
    requirements={}
    unknowns=[]
    for address, summary in summaries.items():
        for sink in summary.sinks:
            key=(sink.function, sink.site, sink.name, sink.offsets, sink.constraints, sink.guards, sink.destinations, sink.weak_kind)
            previous=requirements.get(key)
            requirements[key]=sink if previous is None else replace(previous, dependencies=tuple(dict.fromkeys(previous.dependencies+sink.dependencies)),
                length_dependencies=tuple(dict.fromkeys(previous.length_dependencies+sink.length_dependencies)))
            if sink.weak_kind=='copy_length':
                length_tainted=(True if any(dep.kind=='source' for dep in sink.length_dependencies) else
                    None if sink.length_dependencies else False)
                weak=legacy_copy_weak_kind(bounded=True, buffer_tainted=True, length_tainted=length_tainted)
                if weak=='unknown':unknowns.append({'function':sink.function, 'site':sink.site, 'reason':'Bounded-copy length taint remains unproved'})
                if weak!='copy_length':continue
            for dep in sink.dependencies:
                if dep.kind in ('unknown', 'hash'):
                    unknowns.append(
                        {
                            'function':sink.function,
                            'site':sink.site,
                            'reason':str(dep.value),
                        }
                    )
                    continue
                if dep.kind!='source':continue
                for offset in sink.offsets if sink.kind=='copy' else (None,):
                    length_bounds=uniform_copy_length_constraints(sink.length_dependencies)
                    evidence=WeakEvidence(sink.site, sink.function, sink.name, sink.kind, dep.value,
                        stack_address=None if offset is None else 0x7fffffff-offset, constraints=tuple(dict.fromkeys(dep.constraints+sink.constraints+length_bounds)),
                        constraint_ids=tuple('unresolved-length-recipe-'+str(i) for i in range(len(dep.recipes)+int(dep.unresolved_constraints))),
                        inter_functions=tuple(dict.fromkeys(caller_by_site[site] for site in dep.path if site in caller_by_site)),
                        callsite_path=dep.path, path_scope='Representative may path of actual callsites; function mapping may be partial; not a concrete execution witness',
                        flow_evidence=('CIR backward definitions and procedure summaries',)+dep.guards)
                    decision=policy.classify(evidence)
                    if decision.candidate:
                        key=candidate_key(sink, dep, offset)
                        row=candidates.setdefault(key, {**asdict(decision), 'legacy_weak_kind':sink.weak_kind,
                            'length_sources':sorted({value.value for value in sink.length_dependencies if value.kind=='source'}),
                            'length_constraints':length_bounds,
                            'source_evidence_refs':[{'index':str(source_index_path), 'sha256':source_index_sha,
                                'source_site':dep.value, 'bindings':len(source_evidence_index[dep.value])}]
                                if dep.value in source_evidence_index else [],
                            'caller_projection_incomplete':dep.unresolved_constraints,
                            'source_callsite_paths':[],
                            'source_fact_refs':[],
                            'source_fact_ref_scope':'source-site bucket; no projected callsite path available',
                            'evidence_limit':'Linked source facts and representative may path are not a complete feasibility proof'})
                        path=list(dep.path)
                        if path not in row['source_callsite_paths']:row['source_callsite_paths'].append(path)
                        facts=source_fact_references(tuple(source_evidence_index.get(dep.value, ())), dep)
                        projected=tuple(site for site in dep.path if site!=dep.value)
                        exact=bool(projected and any(fact.get('program_site') in projected for fact in facts))
                        if exact:
                            if not row['source_fact_ref_scope'].startswith('exact'):
                                row['source_fact_refs']=[]
                            row['source_fact_ref_scope']='exact final-round facts at represented caller callsites'
                            row['source_fact_refs']=list(merge_fact_references(tuple(row['source_fact_refs']), facts))
                        elif not row['source_fact_ref_scope'].startswith('exact'):
                            row['source_fact_refs']=list(merge_fact_references(tuple(row['source_fact_refs']), facts))
    pending={address:summary.pending for address, summary in summaries.items() if summary.pending}
    unknown_summary_dependencies=sum(dep.kind in ('unknown', 'hash') for summary in summaries.values()
        for dependencies in (summary.returns, summary.scalar_returns or (), *(deps for slot, deps in summary.outputs),
            *(output.dependencies for output in summary.global_outputs or ())) for dep in dependencies)
    requirement_rows=tuple(requirements.values())
    encoder=EvidenceEncoder()
    encoded_requirements=[encoder.sink(s) for s in requirement_rows]
    requirement_path=phase/'requirements.json'
    write(requirement_path,
        {'requirements':encoded_requirements, 'constraint_recipes':encoder.recipes, 'evidence_format':'P7-evidence-v5'})
    requirement_sha=hashlib.sha256(requirement_path.read_bytes()).hexdigest()
    references=requirement_references(requirement_rows, set(candidates))
    for key, row in candidates.items():
        if not references[key]:
            raise ValueError('A P7 candidate lacks its original source requirement')
        row['requirement_refs']={'file':str(requirement_path), 'sha256':requirement_sha,
            'positions':references[key],
            'scope':'All source requirement alternatives for this weak key; individual legacy policy verdicts may differ'}
    write(phase/'candidates.json', list(candidates.values()))
    write(phase/'unknowns.json', unknowns)
    write(phase/'invocations.json', invocations)
    write(phase/'source-handle-evidence.json', {'source_handle_kinds':{source:sorted(kinds) for source, kinds in handles.items()}, 'legacy_fake_sources':sorted(fake_sources)})
    write(phase/'invalidation-events.json', runtime.events)
    encoder=EvidenceEncoder()
    bank_evidence=[{'table':asdict(root), 'sources':[encoder.dependency(dep) for dep in dependencies]} for root, dependencies in table_bank.items()]
    write(phase/'hsearch-state.json', {'version':table_version, 'tables':bank_evidence, 'constraint_recipes':encoder.recipes, 'events':table_events,
        'semantics':'Original key-insensitive hsearch model; unresolved writer constraints are not rebound to reader arguments'})
    for address, result in last.items():write(phase/('function-'+hex(address)+'.json'), {**result, **summary_evidence(result['summary'])})
    manifest={'phase':'taint', 'engine':'python', 'memory_engine':'apg', 'binary_sha256':store.report['binary_sha256'],
        'functions':len(summaries), 'rounds':rounds, 'invocations':len(invocations), 'source_sites':sorted(sources),
        'buffer_candidate_sites':len({row['evidence']['site'] for row in candidates.values() if row['evidence']['kind']=='copy'}),
        'command_candidate_sites':len({row['evidence']['site'] for row in candidates.values() if row['evidence']['kind']=='command'}),
        'confirmed_findings':0, 'pending_functions':pending, 'pending_summary_functions':[f.rva+store.base for f in todo],
        'candidate_refs_format':CANDIDATE_REFS_FORMAT+' (additive exact Source fact refs; requirements P7-evidence-v5)',
        'legacy_coverage_exclusions':sorted(selected_excluded),
        'coverage':'full-program' if selected is None else 'diagnostic-subset',
        'selected_functions':None if selected is None else sorted(selected),
        'budgets':{'function_seconds':args.function_seconds, 'summary_rounds':args.taint_rounds, 'taint_steps':250000, 'scalar_steps':500000, 'scalar_depth':120, 'dependencies':256},
        'query_scheduling':{'independent_demand_attempts':2, 'shared_argument_ssa':'Function-global caps; reusable at the same actual callsite',
            'soft_shares':'Taint/scalar/memory/time with minimum atomic quanta; all original global caps remain authoritative',
            'source_refinement':'Known callee may-source preserved when optional bound/handle projection is interrupted'},
        'unknown_requirements':len(unknowns), 'unknown_summary_dependencies':unknown_summary_dependencies,
        'status':'incomplete' if selected is not None or pending or todo or unknowns or unknown_summary_dependencies else 'may_fixed_point',
        'icall_input_sha256':hashlib.sha256((folder/'icall-targets.json').read_bytes()).hexdigest(),
        'plt_sha256':store.plt_sha256,
        'wall_seconds':time.monotonic()-started, 'gate_a':'NOT_EVALUATED; requires independent Golden/evidence comparison'}
    manifest['evidence_directory']=str(phase)
    write(phase/'manifest.json', manifest)
    write(folder/('taint.json' if not (folder/'taint.json').exists() else 'taint-'+attempt+'.json'), manifest)
    log_event(LOGGER, 'taint.completed', level=logging.INFO, status=manifest['status'], rounds=rounds,
        invocations=len(invocations), candidates=len(candidates), unknowns=len(unknowns),
        pending_functions=len(pending), wall_seconds=manifest['wall_seconds'], evidence_directory=str(phase))
    return manifest
