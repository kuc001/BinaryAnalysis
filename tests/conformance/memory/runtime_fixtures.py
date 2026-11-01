"""P5 M-01..M-12 executable fixtures with assertions and per-case receipts.

These are bounded semantic fixtures. Whole-firmware iCall/taint is P6/P7.
Native solver statuses and actual legacy differential are separately gated.
"""
from dataclasses import replace
import time
from test_p5_memory import engine
from test_p3_contracts import sample_module,fixture
from emtaint.core import (Endian,Completeness,MemoryObject,MemoryObjectId,ContextId,CallSiteId)
from emtaint.core.contracts import (ValueType,Assessment,Precision,SemanticBudgets,Constant,ValueRef,
    UnsupportedSemantics)
from emtaint.memory import (Offset,Deref,UnknownOffset,AliasKind,ObjectCardinality,ObjectLifetime,
    SymbolicOp,TaintFact,JoinInput)
from emtaint.memory.engine import PythonMemoryEngine
from emtaint.memory.access_graph import AccessGraphArena,accepts
from emtaint.memory.policies import BudgetExceeded,BudgetedWorklist
from emtaint.memory.query_port import QueryBudget
from emtaint.memory.cir import MemoryEffectInterpreter
from emtaint.ir.canonical import StoreEffect,LoadEffect,UnknownEffect
from emtaint.ir.canonical.wire import dumps,loads
from emtaint.solver.memory_lowering import MemorySolverLowering
from emtaint.solver.lowering import LoweringRequest,LoweringStatus


def must_raise(kind,operation):
    try: operation()
    except kind as error: return error
    raise AssertionError('Expected '+kind.__name__)


def m01(e,r):
    a=e.path(r,(Offset(8),),32,Endian.LITTLE,'o0')
    p=e.path(r,(Offset(8),Deref(32,32,Endian.LITTLE)),32,Endian.LITTLE,'o0')
    assert a.deref_count==0 and p.deref_count==1
    assert e.location_from_path(a).offset_lower==8
    assert e.location_from_path(p).object_id is None
    return {'address_derefs':0,'read_derefs':1,'unresolved_deref':'unknown location; no fabricated object'}


def m02(e,r):
    function,context=e.scope.function,e.scope.context;point=e.origins[0].point
    ids=(MemoryObjectId.stack(function,context,'frame1'),MemoryObjectId.stack(function,context,'frame2'),
         MemoryObjectId.global_object(function.binary,'data',0x80),MemoryObjectId.heap(point,context),
         MemoryObjectId.return_value(function,context),MemoryObjectId.unknown(function.binary,'unknown','input','o0'))
    for id_ in ids:
        root=replace(r,object_id=id_,region=id_.kind.value)
        e.add_object(MemoryObject(id_,'fixture storage',64),root,ObjectCardinality.UNKNOWN,
            ObjectLifetime.UNKNOWN,('No distinct-storage proof',))
    registers={'a0':r};registers['a0']=e.roots[ids[3]]
    assert r.object_id!=registers['a0'].object_id and r.object_id in e.objects
    a=e.location(e.roots[ids[0]],0,8,Endian.LITTLE,'o0');b=e.location(e.roots[ids[1]],0,8,Endian.LITTLE,'o0')
    assert e.resolve_alias(e.initial,a,b).kind==AliasKind.MAY
    return {'object_kinds':sorted({x.kind.value for x in e.objects}),'frame_ids_different':True,
            'distinct_frames_without_proof':'may_alias','register_overwrite_preserves_root':True}


def m03(e,r):
    loc=e.location(r,0,32,Endian.LITTLE,'o0');before=e.load(e.initial,loc)
    version=e.store(e.initial,loc,e.dag.constant(0x12345678,32,'o0'),origin='o0')
    after=e.load(version,loc)
    assert e.constant_value(before) is None and e.constant_value(after)==0x12345678
    assert e.resolve_definition(e.reads[-1]).definitions==(version,)
    assert e.versions[version].definition.update.value=='strong'
    return {'before':'unconstrained initial bytes','after':0x12345678,'strong':True,'definitions':1}


def m04(e,r):
    arena=AccessGraphArena(e.scope,e.budgets);word=(Offset(8),Deref(32,32,Endian.LITTLE))
    path=e.path(r,word*1000,32,Endian.LITTLE,'o0');g=arena.intern(path,e.origins[0].point);e.add_graph(g)
    assert accepts(g,path.segments) and accepts(g,word*1001)
    assert not accepts(g,(Offset(16),Deref(32,32,Endian.LITTLE)))
    assert g.summaries[0].soundness==Completeness.COMPLETE
    return {'accepted_input_steps':1000,'accepted_extra_steps':1001,'language_inclusion':'word^k subset word*',
            'heap_alias_proved_by_apg':False}


def m05(e,r):
    p=e.location(r,0,8,Endian.LITTLE,'o0')
    qroot=replace(r,object_id=MemoryObjectId.argument(e.scope.function,1,e.scope.context))
    e.add_object(MemoryObject(qroot.object_id,'possible alias',64),qroot,ObjectCardinality.UNKNOWN,
        ObjectLifetime.EXTERNAL,('Argument points-to unresolved',))
    q=e.location(qroot,0,8,Endian.LITTLE,'o0')
    m=e.store(e.initial,p,e.dag.constant(7,8,'o0'),origin='o0')
    m=e.store(m,q,e.dag.constant(9,8,'o0'),origin='o0');read=e.load(m,p)
    assert e.versions[m].definition.update.value=='weak'
    assert set(e.possible_constants(read))=={7,9}
    assert len(e.resolve_definition(e.reads[-1]).definitions)==2
    unknown=e.location(None,None,8,Endian.LITTLE,'o0')
    assert e.resolve_alias(m,p,unknown).kind==AliasKind.UNKNOWN
    return {'may_candidates':[7,9],'weak':True,'unknown_location_alias':'unknown; not no_alias'}


def m06(e,r):
    results={}
    for endian in Endian:
        loc=e.location(r,0,32,endian,'o0');part=e.location(r,1,16,endian,'o0')
        m=e.store(e.initial,loc,e.dag.constant(0x11223344,32,'o0'),origin='o0')
        m=e.store(m,part,e.dag.constant(0xaabb,16,'o0'),origin='o0')
        actual=e.constant_value(e.load(m,loc));assert actual==0x11aabb44
        results[endian.value]=actual
    wrap=e.location(r,0xfffffffe,32,Endian.LITTLE,'o0')
    m=e.store(e.initial,wrap,e.dag.constant(0x12345678,32,'o0'),origin='o0')
    byte=e.location(r,0,8,Endian.LITTLE,'o0')
    assert e.constant_value(e.load(m,byte))==0x34
    return {'partial_overlap':results,'pointer_wrap_byte_at_zero':0x34,'byte_oracle':'independent randomized regression also required'}


def m07(e,r):
    module=sample_module();address=module.functions[0].values[1];value=module.functions[0].values[0]
    # Seed value semantics explicitly; addresses have separate stable provenance.
    interp=MemoryEffectInterpreter(e,{address.id:e.dag.symbol('p',address.type,'o0'),
        value.id:e.dag.constant(42,32,'o0')},{address.id:(r,0)})
    state=interp.run(module.functions[0].blocks[0].effects)
    assert e.constant_value(interp.values[value.id])==42
    state=interp.apply(state,UnknownEffect('o0','Dirty','Unknown helper memory/control'))
    loc=e.location(r,0,32,Endian.LITTLE,'o0')
    assert e.constant_value(e.load(state,loc)) is None
    assert e.snapshot().assessment.status==Completeness.INCOMPLETE
    unknown=e.dag.make(ValueType.bv(8),SymbolicOp.UNKNOWN,origin='o0',value='helper value')
    assert MemorySolverLowering().lower(LoweringRequest(e.snapshot(),unknown)).status==LoweringStatus.UNSUPPORTED
    return {'cir_store_load':42,'after_unknown_effect':'havoc/unconstrained','helper_lowering':'unsupported'}


def m08(e,r):
    word=(Offset(8),Deref(32,32,Endian.LITTLE));other=(Offset(16),Deref(32,32,Endian.LITTLE))
    growth=[]
    for n in (10,100,1000):
        start=time.perf_counter();local,root=engine();arena=AccessGraphArena(local.scope,local.budgets)
        path=local.path(root,word*n,32,Endian.LITTLE,'o0');graph=arena.intern(path,local.origins[0].point)
        local.add_graph(graph)
        # A MemoryRead is a version/location leaf, not a nested Load chain.
        loc=local.location(None,None,32,Endian.LITTLE,'o0');ref=local.load(local.initial,loc)
        assert local.dag.nodes[ref].operands==() and accepts(graph,path.segments)
        growth.append({'steps':n,**local.metrics(),'wall_seconds':time.perf_counter()-start})
    arena=AccessGraphArena(e.scope,e.budgets)
    tree=arena.field_closure(r,(word,other),e.origins[0].point);e.add_graph(tree)
    assert accepts(tree,word+other+other+word*3+other)
    prev=(Offset(-8),Deref(32,32,Endian.LITTLE))
    double=arena.field_closure(r,(word,prev),e.origins[0].point);e.add_graph(double)
    assert accepts(double,word*3+prev*2+word)
    fixed=BudgetedWorklist();assert fixed.run((0,),lambda item:(1,) if item==0 else (0,))==frozenset((0,1))
    growing=BudgetedWorklist(replace(e.budgets,worklist_iterations=8))
    error=must_raise(BudgetExceeded,lambda:growing.run((0,),lambda depth:(depth+1,)))
    assert growing.pending and error.assessment.status==Completeness.INCOMPLETE
    return {'growth':growth,'tree_and_doubly_linked':'field-alphabet closure; all finite field walks included',
        'finite_cfg_cycle_steps':fixed.accounting.counts['worklist_iterations'],
        'unbounded_recursive_context':'explicit incomplete with pending frontier; no convergence claim',
        'recursive_steps':growing.accounting.counts['worklist_iterations']}


def m09(e,r):
    failures=[]
    def check(label,operation):
        error=must_raise(BudgetExceeded,operation);failures.append({'budget':label,'dimension':error.dimension,'status':error.assessment.status.value})
    tiny=AccessGraphArena(e.scope,replace(e.budgets,apg_nodes=1))
    path=e.path(r,(Offset(1),Offset(2)),32,Endian.LITTLE,'o0')
    check('APG nodes',lambda:tiny.intern(path,e.origins[0].point))
    tiny_edges=AccessGraphArena(e.scope,replace(e.budgets,apg_edges=1))
    check('APG edges',lambda:tiny_edges.intern(path,e.origins[0].point))
    closure=AccessGraphArena(e.scope,replace(e.budgets,apg_summaries=1))
    check('APG summaries',lambda:closure.field_closure(r,((Offset(8),),(Offset(16),)),e.origins[0].point))
    small,root=engine(replace(e.budgets,sse_nodes=1));small.dag.constant(1,8,'o0')
    check('SSE',lambda:small.dag.constant(2,8,'o0'))
    small,root=engine(replace(e.budgets,heap_cells=1));loc=small.location(root,0,16,Endian.LITTLE,'o0')
    check('Heap cells',lambda:small.store(small.initial,loc,small.dag.constant(1,16,'o0'),origin='o0'))
    work=BudgetedWorklist(replace(e.budgets,worklist_iterations=1))
    check('Worklist',lambda:work.run((0,),lambda x:(x+1,)))
    small,root=engine(replace(e.budgets,heap_objects=1));new=replace(root,object_id=MemoryObjectId.argument(e.scope.function,2,e.scope.context))
    check('Heap objects',lambda:small.add_object(MemoryObject(new.object_id,'extra',64),new))
    small,root=engine(replace(e.budgets,worklist_states=1));loc=small.location(root,0,8,Endian.LITTLE,'o0')
    check('Memory states',lambda:small.store(small.initial,loc,small.dag.constant(1,8,'o0'),origin='o0'))
    context=ContextId((CallSiteId(e.origins[0].point),))
    small,root=engine(replace(e.budgets,contexts=1));new=replace(root,object_id=MemoryObjectId.argument(e.scope.function,0,context))
    check('Contexts',lambda:small.add_object(MemoryObject(new.object_id,'callee',64),new))
    new=replace(r,object_id=MemoryObjectId.argument(e.scope.function,3,e.scope.context));e.add_object(MemoryObject(new.object_id,'extra',64),new)
    address=e.dag.symbol('p',ValueType.pointer(32),'o0')
    check('Alias candidates',lambda:e.points_to(e.initial,address,QueryBudget(max_alias_candidates=1)))
    return {'exhaustions':failures,'solver_query_budget':'native probe verifies one actual call then UNKNOWN'}


def m10(e,r):
    loc=e.location(r,0,8,Endian.LITTLE,'o0');m=e.store(e.initial,loc,e.dag.constant(7,8,'o0'),origin='o0')
    value=e.load(m,loc);lowered=MemorySolverLowering().lower(LoweringRequest(e.snapshot(),value))
    assert lowered.status==LoweringStatus.READY and lowered.query.expression.op=='BVV'
    assert lowered.query.expression.args==(7,)
    exhausted=MemorySolverLowering().lower(LoweringRequest(e.snapshot(),value,budget=QueryBudget(max_steps=1)))
    assert exhausted.status==LoweringStatus.INCOMPLETE and exhausted.query is None
    return {'local_lowering':'ready, BVV(7,8), no raw Load/Store','solver_statuses':'native probe required separately',
            'budget_lowering':'incomplete; no query'}


def m11(e,r):
    arena=AccessGraphArena(e.scope,e.budgets)
    graph=arena.field_closure(r,((Offset(8),Deref(32,32,Endian.LITTLE)),),e.origins[0].point);e.add_graph(graph)
    guard=e.dag.symbol('path-guard',ValueType.boolean(),'o0')
    fact=TaintFact('source-to-sink',r,None,graph.id,e.scope.context,e.initial,guard,'may-source-sink','o0',
        ('Source(arg)','arg.next*.data','Sink candidate'),
        Assessment(Completeness.COMPLETE,Precision.OVER_APPROX,('May-flow requires reachability/constraint validation',),diagnostics=()))
    e.add_taint(fact);candidate=e.sink_candidates()[0]
    assert candidate['guard']==guard and candidate['memory_version']==e.initial and not candidate['confirmed']
    assert loads(dumps(e.snapshot())).taint_facts==(fact,)
    from test_p5_taint import tainted
    local,root,tracker,source,g=tainted();loc=local.location(root,0,32,Endian.LITTLE,'o0')
    state=local.store(local.initial,loc,source,g,'o0');read=local.load(state,loc)
    flows=tracker.sink(read,state,'o0')
    assert len(flows)==1 and g in flows[0]['guards'] and not flows[0]['confirmed']
    overwrite=local.store(state,loc,local.dag.constant(0,32,'o0'),origin='o0')
    assert tracker.sink(local.load(overwrite,loc),overwrite,'o0')==()
    assert tracker.sink(read,state,'o0',local.dag.boolean(False,'o0'))==()
    havoc=local.havoc(state,('*',),'unknown external','o0')
    assert tracker.sink(local.load(havoc,loc),havoc,'o0')[0]['status']=='unknown'
    return {'facts':1,'status':'may candidate','guard_preserved':True,'confirmed_findings':0,
        'value_store_load_flow':len(flows),'strong_overwrite_kills_old_flow':True,'false_guard_suppresses_flow':True,
        'havoc_flow':'unknown; never clean','flow_metrics':local.metrics(),
        'scope':'Focused value/definition flow; whole-program discovery, sanitizer summaries and findings are P6/P7'}


def m12(e,r):
    module=sample_module();address=module.functions[0].values[1];value=module.functions[0].values[0]
    def execute(source):
        current,root=engine();harness=MemoryEffectInterpreter(current,
            {address.id:current.dag.symbol('p',address.type,'o0'),value.id:current.dag.constant(42,32,'o0')},
            {address.id:(root,0)})
        harness.run(source.functions[0].blocks[0].effects)
        actual=current.constant_value(harness.values[value.id]);assert actual==42
        return current.snapshot()
    a=execute(module);b=execute(loads(dumps(module)));assert a==b
    assert a.assessment.status==Completeness.COMPLETE
    assert PythonMemoryEngine.from_snapshot(loads(dumps(a))).snapshot()==a
    return {'same_cir_before_after_wire':'same runtime snapshots, values, diagnostics and definitions',
            'memory_wire':'Memory-Semantics-v1','schema_changed':False,'rust':'not executed'}


CASES={f'M-{i:02d}':case for i,case in enumerate((m01,m02,m03,m04,m05,m06,m07,m08,m09,m10,m11,m12),1)}


def exercise(case):
    start=time.perf_counter();e,r=engine();actual=CASES[case](e,r);snapshot=e.snapshot()
    return {'fixture':case,'runtime_gate_m':'PASS','actual':actual,
        'completeness':snapshot.assessment.status.value,'precision':snapshot.assessment.precision.value,
        'precision_loss':list(snapshot.assessment.precision_loss),'unsupported_ops':list(snapshot.assessment.unsupported_ops),
        'metrics':e.metrics(),'peak_rss_bytes':None,'wall_seconds':time.perf_counter()-start,
        'conservativeness':'Exact byte operations or explicit may/unknown/incomplete; no absence-of-facts conclusion',
        'fallback':'memory_engine=legacy requires supplied reference; default path unchanged'}
