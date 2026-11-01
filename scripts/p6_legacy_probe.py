"""Guarded Python 3.7 characterization of real legacy P6 transfer methods."""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import traceback
TARGET=Path(__file__).resolve().parents[1]
from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(TARGET/'.p6-work')
    cache=folder/'cache';cache.mkdir(exist_ok=False)
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    if sys.platform=='win32':ctypes.windll.kernel32.SetErrorMode(3)
    guard=ProbeWriteGuard([folder]).install();report={'python':sys.version,'executable':sys.executable}
    try:
        report['ply_calls']=install_ply_isolation(cache,'disabled')
        package=types.ModuleType('dataflow');package.__path__=[str(TARGET.parent/'EmTaint/dataflow')];sys.modules['dataflow']=package
        from dataflow.fast_data_flow import FastDataFlow,LiveSims
        from dataflow.accurate_data_flow import AccurateDataFlow
        from dataflow.vex_process import Action
        from dataflow.code_location import CodeLocation
        from dataflow.data_collector import Collector
        from dataflow.global_config import arch_info,section_regions,basic_types
        from dataflow.variable_expression import VarExpr,TraceExpr
        from dataflow.sim_procedure import SimProcedure
        package.SimProcedure=SimProcedure
        from dataflow.data_trace import FastSearch
        from dataflow.parse_binary import BinaryParser
        import claripy
        import networkx
        arch_info['bits']=32;section_regions['.loader']=(0,0)
        basic_types['default']=basic_types[32]
        fast=FastDataFlow.__new__(FastDataFlow);fast.gp_name='r9';fast.sp_name='r13'
        locations=[CodeLocation(0x100,i) for i in range(3)]
        actions=[Action('w',locations[0],'t0','r1',32),Action('wo',locations[1],'t1',('+',('t0',8)),32),Action('p',locations[2],'r0','t1',32)]
        block=types.SimpleNamespace(live_defs={a.dst:a for a in actions},actions=dict(zip(locations,actions)),code_locations=locations)
        uses={LiveSims('r0','reg'):{CodeLocation(0x100,3)}};graph=networkx.DiGraph()
        fast.process_block_in_backward(block,uses,graph,set())
        fast_result={'inputs':sorted('reg:'+u.name for u in uses),'edges':sorted((a.stmt_idx,b.stmt_idx) for a,b in graph.edges())}
        accurate=AccurateDataFlow.__new__(AccurateDataFlow)
        accurate.taint_check=False;accurate.arch_bits=32;accurate.sp_name='r13';accurate.backward_store_records=set()
        load=Action('wl',locations[0],'t0',0x2008,32);load.addr_type='G';types_={}
        ast=accurate._get_load_action_ast(load,types.SimpleNamespace(special_flag=0),types_,None)
        load_result={'op':ast.op,'address':ast.args[0].args[0],'width':ast.size(),'args':len(ast.args)}
        def trace(value):
            expr=VarExpr(value,pattern='BF',trace_dir='B',data_type='Iptr',var_type='ptr')
            expr.location=locations[0];expr.source=locations[0]
            expr.get_trace_variable();expr.initial_sims(var_type='ptr');expr.initial_sim_actions(locations[0],var_type='ptr')
            return TraceExpr(expr,10)
        fixture_block=types.SimpleNamespace(is_loop=False,special_flag=0,live_defs={})
        load2=Action('wl',locations[1],'t0',0x1000,32);load2.addr_type='G'
        expanded=accurate._find_wrtmp_load_def_v1(fixture_block,load2,trace(claripy.BVS('t0',32,explicit_name=True)))
        store=Action('s',locations[2],0x1000,0x3000,32);store.addr_value=0x1000;store.var_type='ptr'
        replaced=accurate._do_store_define(fixture_block,store,trace(claripy.Load(claripy.BVV(0x1000,32),32)),trace_dir='B')
        fs=FastSearch.__new__(FastSearch);fs._binary_parser=BinaryParser.__new__(BinaryParser)
        fs._binary_parser.add_ops=['__add__']
        import archinfo
        from dataflow.global_config import default_arg_names,argument_vars
        default_arg_names[:]=['r8','r12','r16','r20']
        fs.proj=types.SimpleNamespace(arch=archinfo.ArchARMEL())
        argument_vars[:]=['r%d'%offset for offset in fs.proj.arch.argument_registers]
        fs._accurate_dataflow=accurate;accurate.sp_name='r60'
        fs._binary_parser.arch_bits=32
        entry=types.SimpleNamespace(addr=0x100,live_defs={})
        fs._initial_stack_in_function_start(types.SimpleNamespace(start_node=entry))
        class Callsite:
            addr=0x120
            def __init__(self):self.backward_exprs=[]
        callsite=Callsite()
        fs._initialize_callsite_arguments(types.SimpleNamespace(callsite_arg_definitions={callsite:[trace(claripy.BVS('r8',32,explicit_name=True))]}))
        accurate.proj=fs.proj;accurate.base_stack=0x7fffffff
        report['entry_and_arguments']={'sp':entry.live_defs['r60'].value,
            'stack_slots':[accurate.judge_stack_argument(0x7fffffff+x) for x in (0,4,8,1,-4)],
            'callsite_arguments':sorted(str(e.expr.ast.args[0]) for e in callsite.backward_exprs),
            'directions':sorted(e.expr.trace_dir for e in callsite.backward_exprs)}
        base=claripy.BVS('r4',32,explicit_name=True);increment=claripy.BVV(4,32)
        remove=[];summary=fs._summary_variable_in_loop({1:(base,increment)},[trace(claripy.Load(base+increment,32))],remove)
        loop_values=[]
        for item in summary:
            address=item.expr.ast.args[0].replace(base,claripy.BVV(0x1000,32))
            address=address.replace(claripy.BVS('i',32,explicit_name=True),claripy.BVV(3,32))
            loop_values.append(claripy.simplify(address).args[0])
        report['accurate_rules']={'load_substitution':[str(e.expr.ast) for e in expanded],
            'load_address':expanded[0].expr.ast.args[0].args[0] if expanded else None,
            'store_substitution':[str(e.expr.ast) for e in replaced],
            'store_value':replaced[0].expr.ast.args[0] if replaced else None,
            'loop_base_1000_i_3':loop_values,'loop_rule':'base + offset * i (old trace keeps zero-th iteration)'}
        section_regions.update({'.data':(0x1000,0x1100),'.text':(0x2000,0x2100),'.loader':(0x1000,0x3000)})
        words={0x1000:0x1040,0x1004:0x1080,0x1040:0x2000,0x1044:0x2004,0x1048:0x3000,
               0x1080:0x2008,0x1084:0x200c,0x1088:0x3000}
        nested_collector=Collector.__new__(Collector)
        nested_collector.state=types.SimpleNamespace(memory=types.SimpleNamespace(
            load=lambda address,size,endness=None:claripy.BVV(words.get(address,0),size*8)))
        nested_collector.size_bytes=4;nested_collector.endness='Iend_LE'
        i=claripy.BVS('i',32,explicit_name=True)
        nested=claripy.Load(claripy.Load(claripy.BVV(0x1000,32)+i*4,32)+i*4,32)
        simplified=nested_collector.replace_load_value(nested,{},{})
        nested_targets=set()
        for expression in simplified:nested_targets.update(nested_collector.calculate_icall_targets(expression,{},[]))
        report['nested_table']={'expressions':[str(x) for x in simplified],'targets':sorted(nested_targets)}
        from p6_reference_probe import scalar_add
        pointer=claripy.Load(claripy.BVV(0x1040,32)+i*4,32)
        normalized=scalar_add(claripy.BVV(0,32),pointer)
        identity_targets=sorted(nested_collector.calculate_icall_targets(normalized,{},[]))
        report['cir_pointer_cast_identity']={'raw_op':(claripy.BVV(0,32)+pointer).op,
            'normalized_op':normalized.op,'same_ast':normalized is pointer,'targets':identity_targets}
        from dataflow.ida_process import IDAProcess
        data=TARGET.parent/'EmTaint/data/ida_data/rv130_1_0_3_44'
        ida=IDAProcess(binary_cfg_info_path=str(data/'httpd_cfg.json'),binary_block_info_path=str(data/'httpd_block_info.json'),
                       icall_info_path=str(data/'httpd_icall.json'),ijmp_info_path=str(data/'httpd_ijmp.json'),binary_name='main')
        node=lambda f:('internal',f.addr) if f.addr else ('external',f.procedural_name)
        cold=sorted((node(a),node(b)) for a,b in ida.cg.graph.edges())
        ida.load_icall_info();ida.add_icall_edge()
        warm=sorted((node(a),node(b)) for a,b in ida.cg.graph.edges())
        with (folder/'legacy-cg.json').open('x',encoding='utf8') as f:
            json.dump({'cold_edges':cold,'warm_edges':warm,'nodes':sorted(node(n) for n in ida.cg.graph.nodes()),
                'input_target_source':'Original httpd_icall.json; independently tagged warm input, not recovered facts'},f,indent=2)
        report['cg']={'cold_edges':len(cold),'warm_edges':len(warm),'nodes':len(ida.cg.graph.nodes())}
        collector=Collector.__new__(Collector);collector.icall_targets={};collector.switch_targets={}
        for target in (0x20,0x20,0x30):collector.add_icall_target(0x100,0x10c,target)
        for target in (0x104,0x104,0x108):collector.add_switch_target(0x100,0x10c,target)
        report.update(fast=fast_result,accurate_load=load_result,icall=collector.icall_targets,switch=collector.switch_targets)
        report['passed']=(fast_result['inputs']==['reg:r1'] and load_result=={'op':'Load','address':0x2008,'width':32,'args':1}
            and collector.icall_targets[0x100][0x10c]==[0x20,0x30]
            and report['accurate_rules']['load_address']==0x1000 and report['accurate_rules']['store_value']==0x3000
            and loop_values==[0x100c] and sorted(nested_targets)==[0x2000,0x2004,0x2008,0x200c])
        report['passed'] &= report['entry_and_arguments']=={'sp':0x7fffffff,'stack_slots':['s0','s1','s2',None,None],'callsite_arguments':['r8'],'directions':['B']}
        report['passed'] &= normalized is pointer and identity_targets==[0x2000,0x2004]
        legacy=TARGET.parent/'EmTaint'
        report['source_hashes']={str(n):hashlib.sha256((legacy/n).read_bytes()).hexdigest() for n in (
            'dataflow/fast_data_flow.py','dataflow/accurate_data_flow.py','dataflow/data_trace.py','dataflow/data_collector.py')}
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations;report['passed']=report.get('passed',False) and not guard.violations
        with (folder/'legacy-report.json').open('x',encoding='utf8') as f:json.dump(report,f,indent=2)
        guard.restore()
    print(json.dumps(report),flush=True);return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
