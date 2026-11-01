"""Capture live old -t callee-to-callsite taint transfer in an isolated copy."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def expression_row(item):
    expr=item.expr
    return {'ast':str(expr.ast)[:220], 'constraints':list(item.constraints),
        'source':str(expr.source), 'taint_source':str(expr.taint_source),
        'is_ret':bool(expr.is_ret), 'flag':expr.flag,
        'data_type':expr.data_type, 'base_ptr':str(expr.base_ptr)}


def register_row(definition):
    return {'value':str(getattr(definition,'value',None))[:160],
        'value_type':type(getattr(definition,'value',None)).__name__,
        'src':str(getattr(definition,'src',None)),
        'src_type':str(getattr(definition,'src_type',None))}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-root',type=Path,required=True)
    parser.add_argument('--capture',type=Path,required=True)
    args=parser.parse_args();run=args.run_root.resolve();capture=args.capture.resolve()
    capture.mkdir(exist_ok=False);cache=capture/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([run,capture]).install()
    report={'scope':'Old -t live 0x1db6c→0x2d228 callee-to-callsite taint transfer',
        'interpreter':sys.executable,'transfers':[],'argument_queries':[],
        'pushes':[],'definition_copies':[],'resolved_constraints':[],
        'collector_transitions':[],'truncated':False}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        sys.path.insert(0,str(run))
        from dataflow.data_trace import FastSearch
        original_transfer=FastSearch._process_callsite_callee_taint_in_forward
        def observed_transfer(self,callsite,caller_function,callee_function,loop,taint_exprs,flow_dir):
            selected=(callsite.addr in (0x2d27c,0x1d0f0) or callee_function.addr in (0x2d228,0x1cf1c)) and len(report['transfers'])<32
            row={'callsite':callsite.addr,'caller':caller_function.addr,
                'callee':callee_function.addr,'flow_dir':flow_dir,
                'incoming':[expression_row(item) for item in taint_exprs[:24]],
                'before_forward':[expression_row(item) for item in callsite.forward_exprs[:32]],
                'before_backward':[expression_row(item) for item in callsite.backward_exprs[:32]]} if selected else None
            result=original_transfer(self,callsite,caller_function,callee_function,loop,taint_exprs,flow_dir)
            if selected:
                row['forward']=[expression_row(item) for item in callsite.forward_exprs[:24]]
                row['backward']=[expression_row(item) for item in callsite.backward_exprs[:24]]
                report['transfers'].append(row)
            elif callsite.addr in (0x2d27c,0x1d0f0) or callee_function.addr in (0x2d228,0x1cf1c):report['truncated']=True
            return result
        FastSearch._process_callsite_callee_taint_in_forward=observed_transfer
        original_arguments=FastSearch._get_argument_taint_info
        def observed_arguments(self,callsite,callee_function,call_type=None):
            result=original_arguments(self,callsite,callee_function,call_type=call_type)
            if callsite.addr==0x2d27c and len(report['argument_queries'])<16:
                report['argument_queries'].append({'callsite':callsite.addr,
                    'callee':callee_function.addr,'call_type':call_type,
                    'incoming':[expression_row(item) for item in callsite.forward_exprs[:24]],
                    'selected':[expression_row(item) for item in result[:24]]})
            return result
        FastSearch._get_argument_taint_info=observed_arguments
        original_push=FastSearch._push_callee_arg_exprs_to_callsite
        def observed_push(self,function):
            selected=function.addr in (0x1db6c,0x2d228,0x1cf1c) and len(report['pushes'])<8
            result=original_push(self,function)
            if selected:
                report['pushes'].append({'function':function.addr,
                    'arg_constraints':[expression_row(item) for item in function.arg_constraints[:24]],
                    'taint_exprs':[expression_row(item) for item in function.taint_exprs[:24]]})
            return result
        FastSearch._push_callee_arg_exprs_to_callsite=observed_push
        original_copy=FastSearch._make_def_copy_to_callsite
        def observed_copy(self,callsite,argument_defines,argument_cons):
            selected=callsite.addr in (0x2d27c,0x2120c,0x1d0f0) and len(report['definition_copies'])<16
            row={'callsite':callsite.addr,
                'incoming':[expression_row(item) for item in argument_defines[:24]],
                'constraints':{str(key):[expression_row(item) for item in values[:12]]
                    for key,values in list(argument_cons.items())[:12]},
                'predecessors':[{'address':pre.addr,
                    'registers':{name:register_row(pre.live_defs[name])
                        for name in ('r8','r12','r16','r20') if name in pre.live_defs}}
                    for pre in list(callsite.predecessors)[:8]]} if selected else None
            result=original_copy(self,callsite,argument_defines,argument_cons)
            if selected:
                row['callsite_exprs']=[expression_row(item) for item in callsite.callsite_exprs[:24]]
                row['predecessor_backward']=[{'address':pre.addr,
                    'facts':[expression_row(item) for item in pre.backward_exprs[:24]]}
                    for pre in list(callsite.predecessors)[:8]]
                report['definition_copies'].append(row)
            return result
        FastSearch._make_def_copy_to_callsite=observed_copy
        original_resolve=FastSearch._check_expr_cons_ids
        def observed_resolve(self,cons_id,cons_info):
            result=original_resolve(self,cons_id,cons_info)
            if 39999 in cons_info.get(cons_id,()) and len(report['resolved_constraints'])<24:
                report['resolved_constraints'].append({'cons_id':cons_id,
                    'values':list(cons_info[cons_id]),
                    'stack':[frame.name+':'+str(frame.lineno)
                        for frame in traceback.extract_stack(limit=7)[:-1]]})
            return result
        FastSearch._check_expr_cons_ids=observed_resolve
        original_collect=FastSearch._get_predecessor_block_backward_exprs
        def observed_collect(self,function,block):
            key=7666950021981258662
            before=tuple(self.collector.constraints.get(key,()))
            result=original_collect(self,function,block)
            after=tuple(self.collector.constraints.get(key,()))
            if before!=after and len(report['collector_transitions'])<16:
                report['collector_transitions'].append({'function':function.addr,
                    'block':block.addr,'before':[expression_row(item) for item in before],
                    'after':[expression_row(item) for item in after],
                    'backward':[expression_row(item) for item in block.backward_exprs[:24]]})
            return result
        FastSearch._get_predecessor_block_backward_exprs=observed_collect
        import main as old_main
        sys.argv=[str(run/'main.py'),'-f','./firmware-binaries/rv130_v44/httpd',
            '-n','rv130','-v','1_0_3_44','-t']
        old_main.main();report['completed']=True
    except BaseException as error:
        traceback.print_exc();report.update(completed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (capture/'old-transfer-report.json').open('x',encoding='utf8') as stream:
            json.dump(report,stream,indent=2,default=str)
        guard.restore()
    return 0 if report['completed'] and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
