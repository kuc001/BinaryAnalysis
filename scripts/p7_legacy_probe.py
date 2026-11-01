"""Read-only execution of actual old source/copy/format/security methods."""
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
sys.path.insert(0,str(TARGET))
from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(TARGET/'.p7-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for key in ('TEMP','TMP','TMPDIR'):os.environ[key]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([folder]).install();report={'python':sys.version,'executable':sys.executable,
        'script_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        package=types.ModuleType('dataflow');package.__path__=[str(TARGET.parent/'EmTaint/dataflow')];sys.modules['dataflow']=package
        from dataflow.sim_procedure import SimProcedure
        package.SimProcedure=SimProcedure
        from dataflow.procedures.stubs.format_parser import FormatParser
        from dataflow.security_check import SecurityCheck
        from dataflow import data_collector as tables
        from dataflow.global_config import arch_info,basic_types,section_regions
        from emtaint.analysis.bugfinder.legacy_policy import WeakEvidence,LegacySecurityPolicy
        from emtaint.procedures.legacy import legacy_format_parameters,legacy_integer_constraints
        import claripy
        import archinfo
        arch_info['bits']=32;basic_types['default']=basic_types[32];section_regions['.loader']=(0x1000,0x2000)
        collector=types.SimpleNamespace(constraints={},datas={'uData':{}})
        policy=[]
        for number,(constraints,size) in enumerate((((),32),((31,),32),((32,),32),((0,1),32),(('S',),32),(('Y',),32),((),-1),((),0x100000))):
            tables.weaks_copy.clear();tables.weaks_copy_length.clear();tables.weaks_command_exec.clear();tables.weaks_only_length.clear()
            expression=types.SimpleNamespace(ast=claripy.BVV((0x7fffffff-size)&0xffffffff,32),memory_size=None,taint_source=0x40)
            trace=types.SimpleNamespace(expr=expression,constraints=list(constraints),cons_ids=[],inter_funcs=('a','b'),inter_icall_level=1,taint_propagaton_level=2,loop_num=0)
            tables.weaks_copy[0x100].append(trace)
            checker=SecurityCheck(collector);checker.check_weaks_copy()
            expected=bool(checker.weaks.get(0x100))
            evidence=WeakEvidence(0x100,0x80,'strcpy','copy',0x40,stack_address=(0x7fffffff-size)&0xffffffff,constraints=constraints)
            actual=LegacySecurityPolicy().classify(evidence).candidate
            policy.append({'case':number,'old':expected,'new':actual,'constraints':constraints,'size':size})
        parser=FormatParser.__new__(FormatParser);parser.block=types.SimpleNamespace(format_args=[])
        formats=[]
        for data in (b'%s %u %08s',b'%*s %20[^ ]',b'%%s',b'%ls'):
            parser.block.format_args=[];parser._find_fmt_parameters([bytes((c,)) for c in data])
            formats.append({'format':data.decode(),'old':parser.block.format_args,'new':list(legacy_format_parameters(data))})
        predecessor=types.SimpleNamespace(irsb=None,func_addr=0x1000,backward_exprs=[],live_defs={})
        block=types.SimpleNamespace(addr=0x1010,predecessors=[predecessor],successors=[],live_defs={})
        procedure=SimProcedure.__new__(SimProcedure);procedure.block=block;procedure.arch=archinfo.ArchARMEL()
        procedure.initial_arguments_taint_source({'r8':'src','r12':'dst',1024:'length'})
        sources=[{'ast':str(t.expr.ast),'kind':t.expr.data_type,'direction':t.expr.trace_dir,
            'source':t.expr.taint_source,'constraints':t.constraints,'flag':t.expr.flag} for t in predecessor.backward_exprs]
        from dataflow.variable_expression import construct_trace_expr
        trace=construct_trace_expr(claripy.BVS('r12',32,explicit_name=True),pattern='LBF',data_type='Tdata',trace_dir='F',
            block_addr=block.addr,stmt_idx=0,index=0,var_type='ptr',base_ptr='r12')
        trace.expr.flag=0x100;trace.expr.taint_source=0x900;trace.expr.ptr_id=0x900
        block.forward_exprs=[trace];block.contain_exprs=lambda x:False;block.is_tainted=0
        predecessor.backward_exprs=[]
        procedure.flow_dir='F';procedure.purpose=0;procedure.display_name='strcpy'
        procedure.reg_taint_propagate('r8','r12')
        copies=[{'ast':str(t.expr.ast),'source':t.expr.taint_source,'direction':t.expr.trace_dir,
            'constraints':t.constraints,'sink':t.expr.taint_loc,'level':t.taint_propagaton_level} for t in predecessor.backward_exprs]
        from dataflow.data_trace import FastSearch
        # The 3.7 reference process loads only this pure policy, without the
        # target 3.12 taint package and its typed CIR imports.
        import importlib.util
        spec=importlib.util.spec_from_file_location('p7_guard_policy',str(TARGET/'emtaint/analysis/taint/guards.py'))
        guard_policy=importlib.util.module_from_spec(spec);sys.modules[spec.name]=guard_policy;spec.loader.exec_module(guard_policy)
        legacy_constraint=guard_policy.legacy_constraint
        search=FastSearch.__new__(FastSearch);constraints=[]
        for kind in (0,1,2,4,5,6):
            for operation in ('eq','ne','lt','le','gt','ge'):
                for bound in (0,1,32,0xffffffff):
                    for pointer in (False,True):
                        trace=types.SimpleNamespace(expr=types.SimpleNamespace(var_type='ptr' if pointer else 'int',ast=claripy.BVS('r12',32)),constraints=[])
                        trace.add_constraint=lambda value:trace.constraints.append(value)
                        killed=search._add_taint_constraint(0x2000,(kind,operation,bound),trace)
                        decision=legacy_constraint(kind,operation,bound,pointer=pointer)
                        constraints.append({'kind':kind,'operation':operation,'bound':bound,'pointer':pointer,
                            'old':[bool(killed),trace.constraints],'new':[decision.kill,list(decision.constraints)]})
        report.update(policy=policy,formats=formats,sources=sources,copies=copies,passed=all(r['old']==r['new'] for r in policy+formats)
            and any(t['kind']=='Tdata' and t['constraints']==[1024] for t in sources))
        report.update(constraints=constraints)
        report['passed'] &= all(r['old']==r['new'] for r in constraints)
        integer_constraints=[]
        for values in ((),(0,),(1,),(4,),(8,),(32,),('S',4),(2,6)):
            trace=types.SimpleNamespace(constraints=list(values));procedure._calculate_atoi_constraint(trace)
            integer_constraints.append({'input':values,'old':trace.constraints,'new':list(legacy_integer_constraints(values))})
        report['integer_constraints']=integer_constraints
        report['passed'] &= all(row['old']==row['new'] for row in integer_constraints)
        from dataflow.procedures.libc.hsearch_r import hsearch_r
        from p5_legacy_probe import packet
        table=hsearch_r.__new__(hsearch_r);table.block=block;table.arch=procedure.arch
        table.flow_dir='F';table.purpose=0;table.get_stack_arg_ptr=lambda name:0x7fff0000
        input_trace=construct_trace_expr(claripy.BVS('r12',32,explicit_name=True),pattern='LBF',data_type='Tdata',trace_dir='F',
            block_addr=block.addr,stmt_idx=0,index=0,var_type='ptr',base_ptr='r12')
        input_trace.expr.flag=0x100;input_trace.expr.taint_source=0x900
        block.forward_exprs=[input_trace];predecessor.backward_exprs=[]
        table.insert_data('r8','r12','s0')
        inserted=predecessor.backward_exprs[-1]
        insert_packet=packet(inserted.expr.ast)
        block.forward_exprs=[inserted];predecessor.backward_exprs=[]
        table.find_data('r20','s0')
        found=predecessor.backward_exprs[-1]
        report['hsearch']={'insert':insert_packet,'find':packet(found.expr.ast),'table_identity':inserted.expr.base_ptr,
            'insert_source':inserted.expr.taint_source,'find_source':found.expr.taint_source,
            'key_sensitive':False,'scope':'Actual old helper methods with explicit ABI stack-slot context'}
        report['passed'] &= inserted.expr.taint_source==found.expr.taint_source==0x900
        from dataflow.generate_cfg import FunctionCFG
        from dataflow.cfg_node import CFGBlock
        from collections import defaultdict
        import networkx
        site_rows=[]
        for funcea,site in ((0x4e330,0x4e504),(0x50c38,0x50e10)):
            cfg=FunctionCFG.__new__(FunctionCFG);cfg.addr=funcea
            cfg.ida_object=types.SimpleNamespace(base_addr=0);cfg.callees=defaultdict(list);cfg.callsites={}
            cfg._graph=networkx.DiGraph()
            native=CFGBlock(site,cfg,func_addr=funcea,node_type='Boring');native.end=site+4
            cfg._nodes={site:native}
            kind,target=cfg._add_irsb_node_to_cfg(types.SimpleNamespace(callsites={site:'strcpy'},contain_blocks=[native]),{}, {})
            site_rows.append({'function':funcea,'native_instruction':site,'legacy_synthetic_site':target.addr,
                'name':target.target,'reason':'Call instruction is already a CFG block address; original method increments synthetic call node address',
                'passed':kind=='call' and target.addr==site+1 and target.target=='strcpy'})
        report['synthetic_call_sites']=site_rows
        report['legacy_cfg_source_sha256']=hashlib.sha256((TARGET.parent/'EmTaint/dataflow/generate_cfg.py').read_bytes()).hexdigest()
        report['passed'] &= all(row['passed'] for row in site_rows)
        report['passed'] &= any(t['ast']=='<BV32 r8>' and t['source']==0x900 and t['sink']==block.addr for t in copies)
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (folder/'legacy-report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
        guard.restore()
    print(json.dumps(report),flush=True);return 0 if report.get('passed') and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
