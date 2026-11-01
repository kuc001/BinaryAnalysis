"""Isolated, read-only old Store-to-Load SimAction transfer probe for P7.3."""
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


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--folder',type=Path,required=True)
    args=parser.parse_args()
    folder=args.folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([folder]).install()
    report={'scope':'Controlled native old AccurateDataFlow._find_concrete_addr_store_def_v1; no target CLI or solver claim',
        'interpreter':sys.executable,'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        package=types.ModuleType('dataflow')
        package.__path__=[str(TARGET.parent/'EmTaint'/'dataflow')]
        sys.modules['dataflow']=package
        import claripy
        from dataflow.accurate_data_flow import AccurateDataFlow
        from dataflow.variable_expression import construct_trace_expr
        from dataflow.code_location import CodeLocation
        from dataflow.global_config import section_regions,basic_types,arch_info
        arch_info['bits']=32;basic_types['default']=basic_types[32]
        section_regions['.loader']=(0x1000,0x2000)
        old_file=TARGET.parent/'EmTaint'/'dataflow'/'accurate_data_flow.py'
        report['old_source_sha256']=hashlib.sha256(old_file.read_bytes()).hexdigest()
        engine=AccurateDataFlow.__new__(AccurateDataFlow)
        address=(0x7fffffff-21384)%(1<<32)
        rows=[]
        for label,store_address,store_width,expected in (
                ('same_stack_cell',address,32,77),
                ('disjoint_stack_cell',address+4,32,None),
                ('partial_overlap_byte',address+1,8,None)):
            trace=construct_trace_expr(claripy.Load(claripy.BVV(address,32),32),
                pattern='OB',data_type='Tdata',trace_dir='B',block_addr=0x4e4e0,
                stmt_idx=0,index=0,var_type='ptr')
            action=types.SimpleNamespace(code_location=CodeLocation(0x4e4dc,1),
                var_type='ptr',value=77,var_size=store_width,src_alias=None,src=77,
                addr_value=store_address)
            block=types.SimpleNamespace(is_loop=False)
            result=engine._find_concrete_addr_store_def_v1(block,action,trace)
            concrete=(result[0].expr.ast.args[0] if result and result[0].expr.ast.op=='BVV' else None)
            rows.append({'case':label,'read_address':address,'store_address':store_address,
                'store_width_bits':store_width,
                'read_actions':[(str(item.name),item.action_data.op) for item in trace.expr.sim_actions.values()],
                'result_count':len(result),'result_constant':concrete,'expected':expected,
                'passed':concrete==expected and bool(result)==(expected is not None)})
        report['cases']=rows;report['passed']=all(row['passed'] for row in rows)
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        report['passed']=report.get('passed',False) and not guard.violations
        with (folder/'legacy-memory-report.json').open('x',encoding='utf8') as stream:
            json.dump(report,stream,indent=2)
        guard.restore()
    return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
