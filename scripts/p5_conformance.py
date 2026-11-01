"""Fresh P5 Gate M fixture receipts and seeded Golden pointer-table replay."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import traceback

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET));sys.path.insert(0,str(TARGET/'tests'))
from p1_runtime import ProbeWriteGuard


def peak_rss():
    if sys.platform!='win32':return None
    class Counters(ctypes.Structure):
        _fields_=[('cb',ctypes.c_ulong),('faults',ctypes.c_ulong)]+[(n,ctypes.c_size_t) for n in
            ('peak','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile')]
    current=ctypes.windll.kernel32.GetCurrentProcess;current.restype=ctypes.c_void_p
    query=ctypes.windll.psapi.GetProcessMemoryInfo
    query.argtypes=[ctypes.c_void_p,ctypes.POINTER(Counters),ctypes.c_ulong]
    counters=Counters();counters.cb=ctypes.sizeof(counters)
    return counters.peak if query(current(),ctypes.byref(counters),counters.cb) else None


def golden_tables():
    from test_p5_memory import engine
    from emtaint.core import Endian
    golden=TARGET.parent/'baselines/rv130_1_0_3_44/20261028T051055Z-96d1c781/icall-targets.json'
    data=json.loads(golden.read_text(encoding='utf8'));cases=[];started=time.perf_counter()
    for function,calls in sorted(data.items(),key=lambda p:int(p[0])):
        for site,targets in sorted(calls.items(),key=lambda p:int(p[0])):
            e,r=engine();m=e.initial
            # Synthetic concrete slots seeded from the approved target lists.
            # This is byte-store/load preservation, not new iCall recovery.
            for i,target in enumerate(targets):
                if type(target) is not int:raise ValueError('This replay expects numeric Golden targets')
                loc=e.location(r,i*4,32,Endian.LITTLE,'o0')
                m=e.store(m,loc,e.dag.constant(target,32,'o0'),origin='o0')
            actual=[e.constant_value(e.load(m,e.location(r,i*4,32,Endian.LITTLE,'o0'))) for i in range(len(targets))]
            assert actual==targets
            cases.append({'function':function,'callsite':site,'targets':len(targets),
                'ordered_values_equal':True,'metrics':e.metrics()})
    return {'passed':True,'source':str(golden),'sha256':hashlib.sha256(golden.read_bytes()).hexdigest(),
        'callsites':len(cases),'target_entries':sum(c['targets'] for c in cases),'cases':cases,
        'scope':'Seeded synthetic concrete pointer tables; not target discovery or full firmware differential',
        'wall_seconds':time.perf_counter()-started}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(TARGET/'.p5-work')
    if not folder.is_dir():raise ValueError('Fresh existing evidence directory required')
    guard=ProbeWriteGuard([folder]).install();report={'cases':[]};started=time.perf_counter()
    try:
        from conformance.memory.runtime_fixtures import CASES,exercise
        for case in CASES:
            cpu=time.process_time();row=exercise(case);row['cpu_seconds']=time.process_time()-cpu
            row['peak_rss_bytes']=peak_rss();row['rss_scope']='Windows process cumulative peak; shared fixture process'
            report['cases'].append(row)
            print(case+' PASS',flush=True)
        report['golden_pointer_table_replay']=golden_tables()
        report['passed']=len(report['cases'])==12 and all(r['runtime_gate_m']=='PASS' for r in report['cases'])
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['wall_seconds']=time.perf_counter()-started;report['violations']=guard.violations
        report['passed']=report.get('passed',False) and not guard.violations
        with (folder/'conformance-report.json').open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
        guard.restore()
    print('P5 conformance '+('PASS' if report['passed'] else 'FAIL'),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
