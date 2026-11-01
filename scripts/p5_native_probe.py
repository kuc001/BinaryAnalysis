"""Guarded target-only memory lowering, real SMT and legacy transport differential."""
import argparse
import ctypes
import faulthandler
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
import time

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET));sys.path.insert(0,str(TARGET/'tests'))
from p1_runtime import ProbeWriteGuard


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--legacy-report',type=Path,required=True)
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p5-work')
    if not folder.is_dir(): raise ValueError('Fresh existing P5 folder required')
    cache=folder/'cache';cache.mkdir(exist_ok=False)
    for key in ('TEMP','TMP','TMPDIR'): os.environ[key]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    if sys.platform=='win32': ctypes.windll.kernel32.SetErrorMode(3)
    faulthandler.enable()
    guard=ProbeWriteGuard([folder]).install()
    rows=[];report={'cases':rows};started=time.perf_counter()
    try:
        from test_p5_memory import engine
        from dataclasses import replace
        from emtaint.core import Endian,Completeness,MemoryObjectId,MemoryObject
        from emtaint.core.contracts import ValueType,UnsupportedSemantics
        from emtaint.memory import SymbolicOp,ObjectCardinality,ObjectLifetime
        from emtaint.memory.query_port import QueryBudget
        from emtaint.solver.memory_lowering import MemorySolverLowering
        from emtaint.solver.lowering import LoweringRequest,LoweringStatus
        from emtaint.solver.port import SolverQuery,Term,SolverStatus
        from emtaint.solver.backends.claripy_adapter import ClaripyAdapter
        from emtaint.compat.sse import LegacyAstPacket,LegacySSEAdapter
        adapter=ClaripyAdapter();lowerer=MemorySolverLowering()

        def solve(name,e,value,expected,values=None,guards=(),operation='eval'):
            request=LoweringRequest(e.snapshot(),value,guards,operation=operation,limit=4)
            result=lowerer.solve(request,adapter)
            lowered=lowerer.last_lowering
            if lowered.query is not None:
                with (folder/(name+'-query.json')).open('x',encoding='utf8') as f: json.dump(lowered.query.to_dict(),f,indent=2)
            row={'name':name,'expected_status':expected.value,'expected_values':values,
                'result':result.to_dict(),'lowering_status':lowered.status.value,
                'precision':lowered.assessment.precision.value,'completeness':lowered.assessment.status.value,
                'precision_loss':list(lowered.assessment.precision_loss),'metrics':e.metrics(),
                'passed':result.status==expected and (values is None or set(result.values)==set(values))}
            rows.append(row)

        e,r=engine();loc=e.location(r,0,32,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,e.dag.constant(42,32,'o0'),origin='o0');value=e.load(m,loc)
        solve('must-store-load',e,value,SolverStatus.SAT,[42])
        equal=e.dag.operation(SymbolicOp.EQ,ValueType.boolean(),(value,e.dag.constant(43,32,'o0')),'o0')
        solve('must-contradiction',e,equal,SolverStatus.UNSAT,operation='check')
        for endian in Endian:
            e,r=engine();whole=e.location(r,0,32,endian,'o0');part=e.location(r,1,16,endian,'o0')
            m=e.store(e.initial,whole,e.dag.constant(0x11223344,32,'o0'),origin='o0')
            m=e.store(m,part,e.dag.constant(0xaabb,16,'o0'),origin='o0')
            solve('partial-'+endian.value,e,e.load(m,whole),SolverStatus.SAT,[0x11aabb44])
        e,r=engine();p=e.location(r,0,8,Endian.LITTLE,'o0')
        q=replace(r,object_id=MemoryObjectId.argument(e.scope.function,1,e.scope.context))
        e.add_object(MemoryObject(q.object_id,'uncertain argument',64),q,ObjectCardinality.UNKNOWN,
            ObjectLifetime.EXTERNAL,('May refer to same storage',))
        qloc=e.location(q,0,8,Endian.LITTLE,'o0')
        m=e.store(e.initial,p,e.dag.constant(7,8,'o0'),origin='o0')
        m=e.store(m,qloc,e.dag.constant(9,8,'o0'),origin='o0')
        solve('may-alias-candidates',e,e.load(m,p),SolverStatus.SAT,[7,9])
        e,r=engine();p=e.location(r,0,8,Endian.LITTLE,'o0')
        m=e.store(e.initial,p,e.dag.constant(7,8,'o0'),origin='o0')
        g=e.dag.symbol('write-guard',ValueType.boolean(),'o0')
        m=e.store(m,p,e.dag.constant(9,8,'o0'),g,'o0');value=e.load(m,p)
        solve('guard-true',e,value,SolverStatus.SAT,[9],(g,))
        ng=e.dag.operation(SymbolicOp.NOT,ValueType.boolean(),(g,),'o0')
        solve('guard-false',e,value,SolverStatus.SAT,[7],(ng,))
        h=e.havoc(m,('*',),'unknown external','o0')
        solve('havoc-unknown-bytes',e,e.load(h,p),SolverStatus.SAT)
        unknown=e.dag.make(ValueType.bv(8),SymbolicOp.UNKNOWN,origin='o0',value='unlowerable helper')
        solve('unsupported-helper',e,unknown,SolverStatus.UNSUPPORTED)
        report['solver_queries']=lowerer.solver_queries

        legacy=json.loads(args.legacy_report.read_text(encoding='utf8'))
        e,r=engine();compat=LegacySSEAdapter(e,{'r0':r},Endian.LITTLE,'o0')
        packets=legacy['cases']['markers']
        load=LegacyAstPacket.from_dict(packets['load']);store=LegacyAstPacket.from_dict(packets['store'])
        path=compat.access_path(load);address=compat.access_path(load.args[0])
        pure=compat.import_value(LegacyAstPacket.from_dict(legacy['cases']['replace']['input']),e.initial)
        x=e.dag.symbol('r0',ValueType.bv(32),'o0')
        pure=e.dag.materialize(e.dag.substitute(pure,{x:e.dag.constant(7,32,'o0')}))
        reject=False
        try: compat.import_value(store,e.initial)
        except UnsupportedSemantics: reject=True
        report['legacy_differential']={'legacy_value':legacy['cases']['replace']['value'],
            'new_value':e.constant_value(pure),'legacy_address_derefs':legacy['cases']['deref']['address_count'],
            'new_address_derefs':address.deref_count,'legacy_load_derefs':legacy['cases']['deref']['load_count'],
            'new_load_derefs':path.deref_count,'path_offset':path.segments[0].delta_bytes,
            'store_without_value_rejected':reject,'characterization_source_hashes':legacy['source_hashes'],
            'passed':e.constant_value(pure)==legacy['cases']['replace']['value']==15 and
                address.deref_count==0 and path.deref_count==1 and path.segments[0].delta_bytes==8 and reject}

        # Real SMT deadline: no injected status on this query.
        pigeons=[Term('BVS',5,('p5-pigeon-'+str(i),)) for i in range(32)]
        eq=lambda a,b:Term('Eq',None,(a,b))
        constraints=[Term('ULT',None,(v,Term('BVV',5,(31,)))) for v in pigeons]
        constraints += [Term('Not',None,(eq(pigeons[i],pigeons[j]),)) for i in range(32) for j in range(i)]
        timeout=adapter.solve(SolverQuery(tuple(constraints),timeout_ms=1,origin='P5 actual 1ms SMT stress'))
        rows.append({'name':'real-1ms-timeout','result':timeout.to_dict(),'passed':timeout.status==SolverStatus.TIMEOUT})
        # UNKNOWN is fault-injected through the actual Z3/Claripy exception path;
        # report it as injection rather than naturally occurring undecidability.
        import z3
        original_check,original_reason=z3.Solver.check,z3.Solver.reason_unknown
        try:
            for i,reason in enumerate(('incomplete','timeout','max. resource limit exceeded')):
                checks=[]
                def injected_check(solver,*args): checks.append(1);return z3.unknown
                z3.Solver.check=injected_check;z3.Solver.reason_unknown=lambda solver:reason
                x=Term('BVS',32,('p5-inject-x-'+str(i),));y=Term('BVS',32,('p5-inject-y-'+str(i),))
                query=SolverQuery((eq(Term('Mul',32,(x,y)),Term('BVV',32,(7,))),),origin='P5 fault injection '+reason)
                result=adapter.solve(query)
                expected=SolverStatus.TIMEOUT if reason=='timeout' else SolverStatus.UNKNOWN
                rows.append({'name':'injected-'+reason,'kind':'fault injection','backend_checks':len(checks),
                    'result':result.to_dict(),'passed':len(checks)>0 and result.status==expected})
        finally: z3.Solver.check,z3.Solver.reason_unknown=original_check,original_reason
        limited=MemorySolverLowering()
        request=LoweringRequest(e.snapshot(),pure,budget=QueryBudget(max_solver_queries=1))
        first=limited.solve(request,adapter);second=limited.solve(request,adapter)
        rows.append({'name':'query-budget','first':first.to_dict(),'second':second.to_dict(),
            'solver_calls':limited.solver_queries,'passed':first.status==SolverStatus.SAT and
                second.status==SolverStatus.UNKNOWN and limited.solver_queries==1})
        report['passed']=all(row['passed'] for row in rows) and report['legacy_differential']['passed']
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['wall_seconds']=time.perf_counter()-started;report['violations']=guard.violations
        report['passed']=report.get('passed',False) and not guard.violations
        with (folder/'native-report.json').open('x',encoding='utf8') as f: json.dump(report,f,indent=2)
        guard.restore()
    print(json.dumps(report),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__': raise SystemExit(main())
