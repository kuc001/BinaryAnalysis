"""Python-3.7-compatible, guarded characterization of actual read-only legacy SSE.

Imports only the dataflow modules under a package namespace, bypassing the
analysis package initializer. No CLI, physical rerun or history output writes.
"""
import argparse
import ctypes
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import types
import traceback

TARGET = Path(__file__).resolve().parents[1]
from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def packet(ast, depth=0):
    if depth > 64: raise ValueError('Characterization packet depth budget')
    return {'op':ast.op,'width':ast.size(),
        'args':[packet(x,depth+1) if hasattr(x,'op') else x for x in ast.args]}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--folder',type=Path,required=True)
    folder=parser.parse_args().folder.resolve();folder.relative_to(TARGET/'.p5-work')
    if not folder.is_dir(): raise ValueError('Fresh existing evidence folder required')
    cache=folder/'cache';cache.mkdir(exist_ok=False)
    for name in ('TEMP','TMP','TMPDIR'): os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    if sys.platform=='win32': ctypes.windll.kernel32.SetErrorMode(3)
    guard=ProbeWriteGuard([folder]).install()
    report={'python':sys.version,'executable':sys.executable,'cases':{},'growth':[]}
    try:
        report['ply_calls']=install_ply_isolation(cache,'disabled')
        import claripy
        legacy=TARGET.parent/'EmTaint'
        package=types.ModuleType('dataflow');package.__path__=[str(legacy/'dataflow')]
        sys.modules['dataflow']=package
        from dataflow.variable_expression import VarExpr,TraceExpr,RecursiveExpr,SimAction
        from dataflow.parse_ast import get_all_deref_info,extract_base_and_offset
        from dataflow.global_config import arch_info,section_regions
        from dataflow.code_location import CodeLocation
        arch_info.update({'bits':32});section_regions['.loader']=(0,0)
        x=claripy.BVS('r0',32,explicit_name=True)
        address=x+8;load=claripy.Load(address,32);store=claripy.Store(address,32)
        expr=VarExpr(address,data_type='Dptr',trace_dir='F',var_type='ptr',base_ptr='r0')
        expr.initial_sims('ptr');expr.alias_id=17
        replaced=expr.replace(x,claripy.BVV(7,32),sub_type='ptr',rep_type='ptr',base_ptr=7)
        trace=TraceExpr(expr,3);trace.guard=x==1;trace.constraints.append(9)
        shallow=trace.copy();deep=trace.deep_copy()
        recursive=RecursiveExpr(expr,3,base=x,offset=8,position=1);recursive.inc_records.append('next')
        rec_copy=recursive.copy();rec_deep=recursive.deep_copy()
        loc=CodeLocation(0x100,2)
        action=SimAction(('r0',8),'+',load,'ptr');action.def_locs.add(loc)
        action_copy=action.copy()
        report['cases']={
            'markers':{'load':packet(load),'store':packet(store),'store_has_value':len(store.args)!=1,
                       'base_offset':extract_base_and_offset(address)[:2]},
            'replace':{'input':packet(address),'output':packet(replaced.ast),'value':replaced.ast.args[0],
                       'alias_preserved':replaced.alias_id==17},
            'trace':{'shallow_expr_shared':shallow.expr is trace.expr,'deep_expr_distinct':deep.expr is not trace.expr,
                     'guard_shared':deep.guard is trace.guard,'constraints_independent':deep.constraints is not trace.constraints},
            'recursive':{'base':packet(recursive.base),'offset':recursive.offset,
                         'shallow_records_shared':rec_copy.inc_records is recursive.inc_records,
                         'deep_records_distinct':rec_deep.inc_records is not recursive.inc_records},
            'action':{'name':list(action.name),'binop':action.binop,'copy_def_locs_distinct':action_copy.def_locs is not action.def_locs,
                      'load_matches':action.load_use('r0',8,CodeLocation(0x101,0)),
                      'already_defined_excluded':not action.load_use('r0',8,loc)},
            'deref':{'address_count':len(get_all_deref_info(address)),
                     'load_count':len(get_all_deref_info(load)),'store_count':len(get_all_deref_info(store))}}
        # No legacy solver invocation: custom markers have no SMT memory model.
        for count in (10,100,1000):
            started=time.perf_counter();ast=x
            for _ in range(count): ast=claripy.Load(ast+8,32)
            visits,depth,unique,stack=0,0,set(),[(ast,1)]
            while stack:
                node,level=stack.pop();visits+=1;depth=max(depth,level);unique.add(id(node))
                stack.extend((a,level+1) for a in node.args if hasattr(a,'op'))
            report['growth'].append({'steps':count,'expanded_nodes':visits,'unique_nodes':len(unique),
                'max_depth':depth,'load_count':count,'wall_seconds':time.perf_counter()-started})
        report['source_hashes']={n:hashlib.sha256((legacy/n).read_bytes()).hexdigest() for n in (
            'dataflow/variable_expression.py','dataflow/parse_ast.py','.venv/Lib/site-packages/claripy/ast/bv.py')}
        report['passed']=(report['cases']['replace']['value']==15 and
            report['cases']['deref']=={'address_count':0,'load_count':1,'store_count':1} and
            not report['cases']['markers']['store_has_value'])
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        report['passed']=report.get('passed',False) and not guard.violations
        with (folder/'legacy-report.json').open('x',encoding='utf8') as out: json.dump(report,out,indent=2)
        guard.restore()
    print(json.dumps(report),flush=True)
    return 0 if report['passed'] else 1


if __name__=='__main__': raise SystemExit(main())
