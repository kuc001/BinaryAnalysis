"""Actual old Collector on detached demand roots from the same frozen CIR.

Python 3.7 compatible. This compares the collector/memory boundary, not a second
independent implementation of the whole old FastSearch. Golden is never input.
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
TARGET=Path(__file__).resolve().parents[1]
from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def scalar_add(left,right):
    """Erase only same-width BV zero identities introduced by CIR casts."""
    if left.size()==right.size():
        if left.op=='BVV' and left.args[0]==0:return right
        if right.op=='BVV' and right.args[0]==0:return left
    return left+right


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--integration',type=Path,required=True);parser.add_argument('--loader',type=Path,required=True)
    parser.add_argument('--functions',type=lambda x:int(x,0),nargs='+')
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p6-work');folder.mkdir(exist_ok=False)
    cache=folder/'cache';cache.mkdir()
    for key in ('TEMP','TMP','TMPDIR'):os.environ[key]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([folder]).install();report={}
    try:
        report['ply_calls']=install_ply_isolation(cache,'disabled')
        package=types.ModuleType('dataflow');package.__path__=[str(TARGET.parent/'EmTaint/dataflow')];sys.modules['dataflow']=package
        from dataflow.data_collector import Collector
        from dataflow.global_config import section_regions,arch_info,basic_types
        import dataflow.data_collector as implementation
        import claripy
        arch_info['bits']=32;basic_types['default']=basic_types[32]
        loader=json.loads((args.loader/'loader.json').read_text(encoding='utf8'))
        section_regions.update({k:tuple(v) for k,v in loader['sections'].items()})
        segment_rows=loader['segments'];segments=[(s['base'],(args.loader/s['file']).read_bytes()) for s in segment_rows]
        section_regions['.loader']=(min(a for a,d in segments),max(a+len(d) for a,d in segments))
        reads=[]
        def read(address,size,endness=None):
            for base,data in segments:
                if base<=address and address+size<=base+len(data):
                    value=int.from_bytes(data[address-base:address-base+size],'little');reads.append((address,size,value))
                    return claripy.BVV(value,size*8)
            return claripy.BVS('unmapped_'+str(address),size*8,explicit_name=True)
        collector=Collector.__new__(Collector);collector.state=types.SimpleNamespace(memory=types.SimpleNamespace(load=read))
        collector.size_bytes=4;collector.endness='Iend_LE'
        implementation.Max_i=0x1000
        invocations=json.loads((args.integration/'invocations.json').read_text(encoding='utf8'))
        latest={row['function']:row['pass'] for row in invocations};rows=[]
        for function,number in sorted(latest.items()):
            if args.functions and function not in args.functions:continue
            path=args.integration/('function-'+hex(function)+'-pass-'+str(number)+'-reference.json')
            for row in json.loads(path.read_text(encoding='utf8')):
                done=[];recipe=row['recipe'];site=row['site'];start=len(reads)
                for index,node in enumerate(recipe['nodes']):
                    op=node['op'];a=[done[i] for i in node['operands']];bits=node['type']['bits'];boolean=node['type']['kind']=='bool';value=node['value'];params=node['params']
                    if op=='constant':result=claripy.BoolV(value) if boolean else claripy.BVV(value,bits)
                    elif op in ('unknown','argument','register','symbol'):
                        name=value if op=='symbol' else 'unknown_'+str(index)
                        result=claripy.BoolS(str(name),explicit_name=True) if boolean else claripy.BVS(str(name),bits,explicit_name=True)
                    elif op=='read':result=claripy.Load(a[0],bits)
                    elif op=='copy':result=a[0]
                    elif op=='add':
                        # CIR's BV->pointer cast is ADD(pointer(0), BV).
                        # Legacy custom Load does not reliably simplify that
                        # identity, and Collector dispatches on the top op.
                        # Erase only a proven same-width scalar zero identity.
                        result=scalar_add(a[0],a[1])
                    elif op=='sub':result=a[0] if a[1].op=='BVV' and a[1].args[0]==0 else a[0]-a[1]
                    elif op=='mul':result=a[0]*a[1]
                    elif op=='and_bits':result=a[0]&a[1]
                    elif op=='or_bits':result=a[0]|a[1]
                    elif op=='xor_bits':result=a[0]^a[1]
                    elif op=='eq':result=a[0]==a[1]
                    elif op=='ult':result=claripy.ULT(*a)
                    elif op=='slt':result=claripy.SLT(*a)
                    elif op=='not':result=claripy.Not(a[0]) if boolean else ~a[0]
                    elif op=='if':result=claripy.If(*a)
                    elif op=='extract':result=claripy.Extract(params[0],params[1],a[0])
                    elif op=='concat':result=claripy.Concat(*a)
                    elif op=='zero_extend':result=claripy.ZeroExt(bits-a[0].size(),a[0])
                    elif op=='sign_extend':result=claripy.SignExt(bits-a[0].size(),a[0])
                    else:raise ValueError('Unimplemented reference scalar '+op)
                    done.append(claripy.simplify(result))
                targets=set();expressions=[]
                for root in recipe['returns']:
                    simplified=collector.replace_load_value(done[root],{},{})
                    expressions.append({'before':str(done[root]),'after':[str(x) for x in simplified],
                        'op':done[root].op,'variables':sorted(done[root].variables)})
                    for expression in simplified:
                        targets.update(collector.calculate_icall_targets(expression,{},[0xa590c] if site in (0x2115c,0x2120c) else []))
                rows.append({'function':function,'site':site,'targets':sorted(targets),'queries':len(reads)-start,
                    'expression_nodes':len(done),'maximum_index':implementation.Max_i,'expressions':expressions})
        with (folder/'reference-facts.json').open('x',encoding='utf8') as stream:json.dump(rows,stream,indent=2)
        facts=json.loads((args.integration/'target-facts.json').read_text(encoding='utf8'))
        expected={(r['function'],r['site']):set(r['targets']) for r in facts}
        differences=[{'function':r['function'],'site':r['site'],'missing':sorted(expected.get((r['function'],r['site']),set())-set(r['targets'])),
                      'extra':sorted(set(r['targets'])-expected.get((r['function'],r['site']),set()))} for r in rows]
        report.update(sites=len(rows),targets=sum(len(r['targets']) for r in rows),differences=differences,
            memory_queries=len(reads),maximum_index=implementation.Max_i,
            passed=len(rows)==15 and all(not r['missing'] and not r['extra'] for r in differences),
            scope='Same CIR demand roots, same relocated bytes, same legacy table index/address bounds; actual old Collector only')
        with (folder/'memory-queries.json').open('x',encoding='utf8') as stream:json.dump(reads,stream)
    except BaseException as error:
        traceback.print_exc();report.update(passed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations;report['passed']=report.get('passed',False) and not guard.violations
        with (folder/'reference-report.json').open('x',encoding='utf8') as stream:json.dump(report,stream,indent=2)
        guard.restore()
    print(json.dumps(report),flush=True);return 0 if report['passed'] else 1


if __name__=='__main__':raise SystemExit(main())
