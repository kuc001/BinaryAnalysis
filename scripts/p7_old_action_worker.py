"""Run the old -t in an approved physical copy and snapshot target memory actions."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def action_row(action):
    location=action.code_location
    return {'block':location.block_addr,'statement':location.stmt_idx,
        'instruction':getattr(location,'ins_addr',None),'type':action.action_type,
        'width':action.var_size,'dst':str(action.dst)[:120],
        'src':str(action.src)[:120],'dst_alias':str(action.dst_alias)[:160],
        'src_alias':str(action.src_alias)[:160],'addr_value':action.addr_value,
        'value':str(action.value)[:120],'addr_type':action.addr_type,
        'src_type':action.src_type,'var_type':action.var_type}


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--run-root',type=Path,required=True)
    parser.add_argument('--capture',type=Path,required=True)
    args=parser.parse_args();run=args.run_root.resolve();capture=args.capture.resolve()
    capture.mkdir(exist_ok=False);cache=capture/'cache';cache.mkdir()
    for name in ('TEMP','TMP','TMPDIR'):os.environ[name]=str(cache)
    tempfile.tempdir=str(cache);sys.dont_write_bytecode=True
    guard=ProbeWriteGuard([run,capture]).install()
    report={'scope':'Actual isolated old -t memory Action/SimAction trace for 0x4e330; instrumentation is observational',
        'run_root':str(run),'capture':str(capture),'interpreter':sys.executable,
        'actions':[],'store_transfers':[],'action_truncated':False,'transfer_truncated':False}
    try:
        report['ply']=install_ply_isolation(cache,'disabled')
        sys.path.insert(0,str(run))
        from dataflow.vex_process import EngineVEX
        from dataflow.accurate_data_flow import AccurateDataFlow
        original_parse=EngineVEX.execute_block_irsb_v4
        def parsed(self,function,block,*rest):
            result=original_parse(self,function,block,*rest)
            if getattr(block,'func_addr',None)==0x4e330 and 0x4e4c0<=block.addr<=0x4e520:
                for action in block.actions.values():
                    if len(report['actions'])<512:report['actions'].append(action_row(action))
                    else:report['action_truncated']=True
            return result
        EngineVEX.execute_block_irsb_v4=parsed
        original_store=AccurateDataFlow._do_store_define
        def store(self,block,action,trace_expr,*rest,**kwargs):
            result=original_store(self,block,action,trace_expr,*rest,**kwargs)
            if getattr(block,'func_addr',None)==0x4e330 and 0x4e4c0<=block.addr<=0x4e520:
                relevant=any(item.name and item.name[0]==0x7fffac77
                    for item in trace_expr.expr.sim_actions.values())
                if relevant:
                    if len(report['store_transfers'])<512:
                        report['store_transfers'].append({'action':action_row(action),
                            'read_actions':[(str(item.name),item.action_data.op,item.live)
                                for item in trace_expr.expr.sim_actions.values()],
                            'result_count':len(result or ()),
                            'result_ast':[str(item.expr.ast)[:200] for item in (result or ())[:8]]})
                    else:report['transfer_truncated']=True
            return result
        AccurateDataFlow._do_store_define=store
        import main as old_main
        sys.argv=[str(run/'main.py'),'-f','./firmware-binaries/rv130_v44/httpd',
            '-n','rv130','-v','1_0_3_44','-t']
        old_main.main()
        report['completed']=True
    except BaseException as error:
        traceback.print_exc();report.update(completed=False,error=type(error).__name__+': '+str(error))
    finally:
        report['violations']=guard.violations
        with (capture/'old-action-report.json').open('x',encoding='utf8') as stream:
            json.dump(report,stream,indent=2,default=str)
        guard.restore()
    return 0 if report['completed'] and not report['violations'] else 1


if __name__=='__main__':raise SystemExit(main())
