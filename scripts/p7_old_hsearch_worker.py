"""Observe the old hsearch_r FIND transfer in an approved physical -t copy."""
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
    return {'ast':str(expr.ast)[:320], 'base_ptr':str(expr.base_ptr)[:100],
        'constraints':str(getattr(expr,'constraints',()))[:180],
        'flag':getattr(expr,'flag',None),
        'source':str(getattr(expr,'source',None))[:100]}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-root',type=Path,required=True)
    parser.add_argument('--capture',type=Path,required=True)
    args=parser.parse_args();run=args.run_root.resolve();capture=args.capture.resolve()
    capture.mkdir(exist_ok=False);cache=capture/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([run,capture]).install()
    report={'scope':'Old -t hsearch_r FIND 0x1cf60 observational forward/backward transfer',
        'run_root':str(run),'capture':str(capture),'interpreter':sys.executable,
        'find_calls':[],'truncated':False}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        sys.path.insert(0,str(run))
        from dataflow.procedures.libc.hsearch_r import hsearch_r
        original=hsearch_r.find_data
        def observed(self,retptr,htab):
            block=self.block
            selected=getattr(block,'func_addr',None)==0x1cf1c and block.addr==0x1cf60
            if selected and len(report['find_calls'])<64:
                predecessors=tuple(block.predecessors)
                counts={id(pre):len(pre.backward_exprs) for pre in predecessors}
                forward=[expression_row(item) for item in block.forward_exprs[:64]]
                result=original(self,retptr,htab)
                generated=[{'block':pre.addr,'expressions':[expression_row(item)
                    for item in pre.backward_exprs[counts[id(pre)]:][:16]]} for pre in predecessors]
                report['find_calls'].append({'block':block.addr,'function':block.func_addr,
                    'retptr':str(retptr),'htab':str(htab),'forward':forward,
                    'forward_count':len(block.forward_exprs),'generated':generated})
                return result
            if selected:report['truncated']=True
            return original(self,retptr,htab)
        hsearch_r.find_data=observed
        import main as old_main
        sys.argv=[str(run/'main.py'),'-f','./firmware-binaries/rv130_v44/httpd',
            '-n','rv130','-v','1_0_3_44','-t']
        old_main.main();report['completed']=True
    except BaseException as error:
        traceback.print_exc();report.update(completed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (capture/'old-hsearch-report.json').open('x',encoding='utf8') as stream:
            json.dump(report,stream,indent=2,default=str)
        guard.restore()
    return 0 if report['completed'] and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
