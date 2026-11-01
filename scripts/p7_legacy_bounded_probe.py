"""Actual old bounded-copy marking/collection, in a guarded native process.

Controlled trace inputs and a constant constraint resolver isolate the original
flag/taint_loc rule. This is not a legacy CLI run or a complete binary analysis.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
import types
from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET))


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True;guard=ProbeWriteGuard([folder]).install()
    report={'executable':sys.executable,'python':sys.version,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        'scope':'Actual native old reg_taint_propagate and Collector; controlled trace/constraint inputs; not old CLI'}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        package=types.ModuleType('dataflow');package.__path__=[str(TARGET.parent/'EmTaint/dataflow')];sys.modules['dataflow']=package
        from dataflow.sim_procedure import SimProcedure
        package.SimProcedure=SimProcedure
        from dataflow.variable_expression import construct_trace_expr
        from dataflow import data_collector as tables
        from dataflow.global_config import arch_info,basic_types,section_regions
        import claripy
        import archinfo
        from emtaint.procedures.legacy import legacy_copy_weak_kind,legacy_copy_length_constraints
        arch_info['bits']=32;basic_types['default']=basic_types[32];section_regions['.loader']=(0x1000,0x2000)
        rows=[]
        cases=(('strcpy',True,False,False),('strncpy',True,False,True),
            ('strncpy',True,True,True),('memcpy',False,True,True))
        for name,buffer_tainted,length_tainted,bounded in cases:
            for table in (tables.weaks_copy,tables.weaks_copy_length,tables.weaks_only_length):table.clear()
            previous=types.SimpleNamespace(irsb=None,func_addr=0x1000,backward_exprs=[],live_defs={})
            block=types.SimpleNamespace(addr=0x1010,func_addr=0x1000,predecessors=[previous],successors=[],
                live_defs={},forward_exprs=[],contain_exprs=lambda expr:False,is_tainted=0)
            procedure=SimProcedure.__new__(SimProcedure);procedure.block=block;procedure.arch=archinfo.ArchARMEL()
            procedure.flow_dir='F';procedure.purpose=0;procedure.display_name=name
            procedure.get_constraint=lambda operand,cons_type:([16],None)
            for register,kind,source,enabled in (('r12','ptr',0x900,buffer_tainted),('r16','int',0x901,length_tainted)):
                if not enabled:continue
                trace=construct_trace_expr(claripy.BVS(register,32,explicit_name=True),pattern='LBF',data_type='Tdata',
                    trace_dir='F',block_addr=block.addr,stmt_idx=0,index=0,var_type=kind,base_ptr=register)
                trace.expr.flag=0x100;trace.expr.taint_source=source;trace.expr.ptr_id=source
                if kind=='int':trace.expr.cons_type=4;trace.constraints=[99]
                block.forward_exprs.append(trace)
            procedure.reg_taint_propagate('r8','r12',constraint='r16' if bounded else None,copy_type=int(name=='memcpy'))
            generated=[]
            collector=tables.Collector.__new__(tables.Collector)
            for trace in previous.backward_exprs:
                generated.append({'source':trace.expr.taint_source,'flag':trace.expr.flag,'taint_loc':trace.expr.taint_loc,
                    'constraints':trace.constraints,'ast':str(trace.expr.ast)})
                located=trace.replace(trace.expr.ast,claripy.BVV(0x7fffffff-32,32),rep_type='ptr')
                collector.collect_weaks(block,located)
            actual={'copy':len(tables.weaks_copy[block.addr]),'copy_length':len(tables.weaks_copy_length[block.addr]),
                'only_length':len(tables.weaks_only_length[block.addr])}
            expected={'copy':int(buffer_tainted and not bounded),'copy_length':int(buffer_tainted and bounded and length_tainted),
                'only_length':int(name=='memcpy' and length_tainted)}
            migrated=legacy_copy_weak_kind(bounded=bounded,buffer_tainted=buffer_tainted,length_tainted=length_tainted)
            marked='copy' if actual['copy'] else 'copy_length' if actual['copy_length'] else None
            rows.append({'name':name,'buffer_tainted':buffer_tainted,'length_tainted':length_tainted,'bounded':bounded,
                'generated':generated,'actual':actual,'expected':expected,'migrated_weak_kind':migrated,
                'passed':actual==expected and migrated==marked})
        native_bounds=[]
        for kind,constraints in ((4,(99,0,100)),(5,(16,)),(0,(32,)),(4,('S',)),(4,(1,))):
            values=[];procedure._calculate_copy_lenght_constraint(values,[types.SimpleNamespace(expr=types.SimpleNamespace(cons_type=kind),constraints=list(constraints))])
            migrated=list(legacy_copy_length_constraints(((kind,constraints),)))
            native_bounds.append({'kind':kind,'input':constraints,'old':values,'new':migrated,'passed':values==migrated})
        report.update(cases=rows,passed=all(row['passed'] for row in rows),source_sha256={name:hashlib.sha256(
            (TARGET.parent/'EmTaint/dataflow'/name).read_bytes()).hexdigest() for name in ('sim_procedure.py','data_collector.py')})
        report['length_constraints']=native_bounds;report['passed'] &= all(row['passed'] for row in native_bounds)
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (folder/'legacy-bounded-report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
        guard.restore()
    print(json.dumps(report),flush=True);return 0 if report.get('passed') and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
