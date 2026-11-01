"""Observe the two real old -t iCall transfers in a fresh physical copy."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


SITES=frozenset((0x212d8,0x21404))


def expression_row(item):
    expr=item.expr
    return {'ast':str(expr.ast)[:180], 'source':str(expr.source),
        'taint_source':str(expr.taint_source), 'constraints':list(item.constraints),
        'flag':expr.flag, 'data_type':expr.data_type}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-root',type=Path,required=True)
    parser.add_argument('--capture',type=Path,required=True)
    args=parser.parse_args();run=args.run_root.resolve();capture=args.capture.resolve()
    capture.mkdir(exist_ok=False);cache=capture/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([run,capture]).install()
    report={'scope':'Old -t actual 0x212d8/0x21404→0x18590 transfer',
        'interpreter':sys.executable,'transfers':[],'definition_copies':[],
        'truncated':False}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        sys.path.insert(0,str(run))
        from dataflow.data_trace import FastSearch
        original_transfer=FastSearch._process_callsite_callee_taint_in_forward

        def observed_transfer(self,callsite,caller_function,callee_function,loop,taint_exprs,flow_dir):
            selected=callsite.addr in SITES and callee_function.addr==0x18590
            row=None
            if selected and len(report['transfers'])<64:
                row={'callsite':callsite.addr,'caller':caller_function.addr,
                    'callee':callee_function.addr,'flow_dir':flow_dir,
                    'incoming':[expression_row(item) for item in taint_exprs[:32]],
                    'before_forward':[expression_row(item) for item in callsite.forward_exprs[:32]]}
            result=original_transfer(self,callsite,caller_function,callee_function,loop,taint_exprs,flow_dir)
            if row is not None:
                row['after_forward']=[expression_row(item) for item in callsite.forward_exprs[:32]]
                report['transfers'].append(row)
            elif selected:report['truncated']=True
            return result

        FastSearch._process_callsite_callee_taint_in_forward=observed_transfer
        original_copy=FastSearch._make_def_copy_to_callsite

        def observed_copy(self,callsite,argument_defines,argument_cons):
            selected=callsite.addr in SITES
            row=None
            if selected and len(report['definition_copies'])<64:
                row={'callsite':callsite.addr,
                    'incoming':[expression_row(item) for item in argument_defines[:32]],
                    'before':[expression_row(item) for item in callsite.callsite_exprs[:32]]}
            result=original_copy(self,callsite,argument_defines,argument_cons)
            if row is not None:
                row['after']=[expression_row(item) for item in callsite.callsite_exprs[:32]]
                report['definition_copies'].append(row)
            elif selected:report['truncated']=True
            return result

        FastSearch._make_def_copy_to_callsite=observed_copy
        import main as old_main
        sys.argv=[str(run/'main.py'),'-f','./firmware-binaries/rv130_v44/httpd',
            '-n','rv130','-v','1_0_3_44','-t']
        old_main.main();report['completed']=True
    except BaseException as error:
        traceback.print_exc();report.update(completed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (capture/'old-two-callsite-report.json').open('x',encoding='utf8') as stream:
            json.dump(report,stream,indent=2,default=str)
        guard.restore()
    return 0 if report['completed'] and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
