"""Observe old fread callsite argument state in an isolated -t copy."""
import argparse
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def definition_row(value):
    return {'value':str(getattr(value,'value',None))[:160],
        'value_type':type(getattr(value,'value',None)).__name__,
        'src':str(getattr(value,'src',None))[:160],
        'src_type':str(getattr(value,'src_type',None))[:80],
        'var_type':str(getattr(value,'var_type',None))[:80]}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-root',type=Path,required=True)
    parser.add_argument('--capture',type=Path,required=True)
    args=parser.parse_args();run=args.run_root.resolve();capture=args.capture.resolve()
    capture.mkdir(exist_ok=False);cache=capture/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([run,capture]).install()
    report={'scope':'Old -t 0x2d27c→0x1db6c callsite argument context and setup',
        'run_root':str(run),'capture':str(capture),'interpreter':sys.executable,
        'contexts':[],'argument_setup':[],'truncated':False}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        sys.path.insert(0,str(run))
        from dataflow.vex_process import EngineVEX
        from dataflow.data_trace import FastSearch
        original_context=EngineVEX.set_concret_contexts
        def observed_context(self,callsite,function):
            selected=getattr(callsite,'addr',None)==0x2d27c
            predecessors=tuple(callsite.predecessors) if selected else ()
            before=[{'block':pre.addr,'registers':{name:definition_row(pre.live_defs[name])
                for name in ('r0','r4','r8','r12','r16','r20','r40') if name in pre.live_defs}}
                for pre in predecessors[:8]]
            result=original_context(self,callsite,function)
            if selected and len(report['contexts'])<64:
                report['contexts'].append({'callsite':callsite.addr,
                    'callee':getattr(getattr(function,'start_node',None),'addr',None),
                    'callee_arguments':list(getattr(function,'arguments',())),
                    'predecessor_count':len(predecessors),'predecessors':before,
                    'concret_contexts':dict(function.concret_contexts)})
            elif selected:report['truncated']=True
            return result
        EngineVEX.set_concret_contexts=observed_context
        original_setup=FastSearch._initialize_callsite_arguments
        def observed_setup(self,function):
            result=original_setup(self,function)
            if getattr(getattr(function,'start_node',None),'addr',None)==0x2d228:
                for callsite,definitions in function.callsite_arg_definitions.items():
                    if callsite.addr!=0x2d27c:continue
                    if len(report['argument_setup'])<32:
                        report['argument_setup'].append({'callsite':callsite.addr,
                            'definition_count':len(definitions),
                            'definitions':[str(item.expr.ast)[:180] for item in definitions[:32]],
                            'backward_count':len(callsite.backward_exprs),
                            'backward':[str(item.expr.ast)[:180] for item in callsite.backward_exprs[:32]]})
                    else:report['truncated']=True
            return result
        FastSearch._initialize_callsite_arguments=observed_setup
        import main as old_main
        sys.argv=[str(run/'main.py'),'-f','./firmware-binaries/rv130_v44/httpd',
            '-n','rv130','-v','1_0_3_44','-t']
        old_main.main();report['completed']=True
    except BaseException as error:
        traceback.print_exc();report.update(completed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (capture/'old-context-report.json').open('x',encoding='utf8') as stream:
            json.dump(report,stream,indent=2,default=str)
        guard.restore()
    return 0 if report['completed'] and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
