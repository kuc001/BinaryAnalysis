"""P7 focused source/guard queries through P5 lowering and real Claripy."""
import argparse
from dataclasses import asdict
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET));sys.path.insert(0,str(TARGET/'tests'))
from p1_runtime import ProbeWriteGuard


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for key in ('TEMP','TMP','TMPDIR'):os.environ[key]=str(cache)
    tempfile.tempdir=str(cache);guard=ProbeWriteGuard([folder]).install();report={}
    try:
        from test_p5_memory import engine
        from emtaint.compat.memory_runtime import MemoryRuntimePort
        from emtaint.analysis.taint.regions import RegionTaintTracker
        from emtaint.core.contracts import ValueType
        from emtaint.memory import SymbolicOp
        from emtaint.solver.memory_lowering import MemorySolverLowering
        from emtaint.solver.lowering import LoweringRequest
        from emtaint.solver.port import SolverStatus
        from emtaint.solver.backends.claripy_adapter import ClaripyAdapter
        e,root=engine();p=MemoryRuntimePort(e);tracker=RegionTaintTracker(p)
        loc=e.location(root,0,8,e.architecture.endian,'o0')
        g=p.symbol('actual-source-guard',ValueType.boolean(),'o0')
        byte=p.symbol('source-input-byte',ValueType.bv(8),'o0')
        state=p.write(e.initial,loc,byte,g,'o0').state
        binding=tracker.bind(state,loc,0x1234,'o0',guard=g,provenance=('P7 focused source guard fixture',))
        flows=tracker.query(state,loc,'o0');assert flows and not flows[0].confirmed
        neg=p.operation(SymbolicOp.NOT,ValueType.boolean(),(g,),'o0')
        truth=p.constant(True,ValueType.boolean(),'o0');lowerer=MemorySolverLowering();adapter=ClaripyAdapter();rows=[]
        for name,expression,guards,expected in (
            ('source-guard-feasible',truth,(g,),SolverStatus.SAT),
            ('contradictory-source-sink-guards',truth,(g,neg),SolverStatus.UNSAT),
            ('unsupported-guard-stays-unsupported',p.unknown(ValueType.boolean(),'o0','unlowered guard helper'),(),SolverStatus.UNSUPPORTED)):
            result=lowerer.solve(LoweringRequest(e.snapshot(),expression,guards,operation='check'),adapter)
            row={'name':name,'status':result.status.value,'expected':expected.value,'confirmed':False,
                 'lowering':lowerer.last_lowering.status.value,'passed':result.status==expected}
            if lowerer.last_lowering.query is not None:row['query']=lowerer.last_lowering.query.to_dict()
            rows.append(row)
        report={'cases':rows,'source_fact':asdict(binding.fact),'metrics':p.metrics(),
            'solver_queries':lowerer.solver_queries,'passed':all(row['passed'] for row in rows),
            'scope':'Focused fixtures; no claim about whole-program candidate feasibility'}
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (folder/'solver-report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2,default=str)
        guard.restore()
    print(json.dumps({'passed':report.get('passed'),'violations':report['violations']}))
    return 0 if report.get('passed') and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
