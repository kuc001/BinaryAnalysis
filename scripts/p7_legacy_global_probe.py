"""Read-only characterization of actual old global definition/taint methods."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback
import types

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET/'scripts'))
from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);guard=ProbeWriteGuard([folder]).install()
    report={'executable':sys.executable,'python':sys.version,'scope':'Actual old global methods with controlled native TraceExpr; not old CLI',
        'producer_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        package=types.ModuleType('dataflow');package.__path__=[str(TARGET.parent/'EmTaint/dataflow')];sys.modules['dataflow']=package
        from dataflow.sim_procedure import SimProcedure
        package.SimProcedure=SimProcedure
        from dataflow.global_config import arch_info,basic_types,section_regions
        arch_info['bits']=32;basic_types['default']=basic_types[32];section_regions['.loader']=(0x1000,0x4000)
        from dataflow.data_trace import FastSearch
        from dataflow.function_object import FunctionAttribute
        from dataflow.variable_expression import construct_trace_expr
        import claripy
        trace=construct_trace_expr(claripy.BVV(0x2000,32),pattern='LBF',data_type='Tdata',trace_dir='F',
            block_addr=0x1010,stmt_idx=0,index=0,var_type='ptr',base_ptr=0x2000)
        trace.expr.taint_source=0x900;trace.inter_funcs=['1000']
        search=FastSearch.__new__(FastSearch);caller=FunctionAttribute(0x1000)
        exported=search._get_argument_def_exprs(caller,[trace])
        second=trace.deep_copy();second.expr.taint_source=0xa00
        from dataflow.code_location import CodeLocation
        second.expr.source=CodeLocation(0x1020,0)
        merged=search._get_argument_def_exprs(caller,[trace,second])
        callee=FunctionAttribute(0x3000);callsite=types.SimpleNamespace(node_type='iCall')
        callee.merge_input_global_taints_v1(callsite,{0x2000:[trace]})
        callee.merge_input_global_taints_v1(callsite,{0x2000:[trace]})
        incoming=callee.input_global_taints[0x2000]
        block=types.SimpleNamespace(global_addrs={0x2000},traced_iids=set(),global_defs={0x2000})
        forwarded=[];callee.get_global_taints(block,forwarded);callee.get_global_taints(block,forwarded)
        callee.kill_input_global_taints(block)
        other=FunctionAttribute(0x3000);other.merge_input_global_taints_v2(callsite,[trace])
        report.update(exported=[{'scope':value.expr.scope,'base':value.expr.base_ptr,'source':value.expr.taint_source} for value in exported],
            merged_same_global=[{'scope':value.expr.scope,'base':value.expr.base_ptr,'source':value.expr.taint_source} for value in merged],
            incoming=[{'base':value.expr.base_ptr,'source':value.expr.taint_source,'functions':value.inter_funcs,
                'indirect_depth':value.inter_icall_level,'index':value.index} for value in incoming],
            forwarded_count=len(forwarded),killed=not callee.input_global_taints,
            from_callsite_count=len(other.input_global_taints.get(0x2000,())))
        report['passed']=(len(exported)==1 and exported[0].expr.scope=='global' and len(incoming)==1
            and incoming[0].expr.taint_source==0x900 and incoming[0].inter_icall_level==1 and len(forwarded)==1
            and not callee.input_global_taints and len(other.input_global_taints.get(0x2000,()))==1 and len(merged)==1)
        report['legacy_source_sha256']={name:hashlib.sha256((TARGET.parent/'EmTaint/dataflow'/name).read_bytes()).hexdigest()
            for name in ('data_trace.py','function_object.py','variable_expression.py')}
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (folder/'report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
        guard.restore()
    print(json.dumps(report));return 0 if report.get('passed') and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
