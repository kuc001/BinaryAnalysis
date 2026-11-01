"""Dispatch protocol only: mocks never execute or copy the old repository."""
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from scripts import p7_legacy_reference as reference


class LegacyDispatchTests(unittest.TestCase):
    def test_i_and_t_execute_separate_stages_with_the_same_plan(self):
        base=reference.TARGET/'.p7-work/test-legacy-dispatch';base.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root=Path(temporary).resolve();root.relative_to(base.resolve())
            output=root/'output';output.mkdir();run=root/'physical-copy/EmTaint';archive=root/'archive'
            plan=reference.plan_for(output);plan['isolation_reference']=str(root/'proof.json')
            proof={'verified':True,'bootstrap_sha256':plan['bootstrap_sha256'],'contract':{'fixture':True}}
            reference.baseline.write_json(root/'proof.json',proof)
            plan_path=root/'plan.json';reference.baseline.write_json(plan_path,plan)
            args=SimpleNamespace(legacy_plan=str(plan_path),binary_file=str(reference.baseline.LEGACY/reference.baseline.REL_BINARY),
                firmware_name='rv130',firmware_version='1_0_3_44',icall_check=True)
            def copy(*arguments):
                run.mkdir(parents=True)
                for path in (reference.baseline.REL_RESULT,reference.baseline.REL_META/'httpd_icall.json'):
                    destination=run/path;destination.parent.mkdir(parents=True,exist_ok=True)
                    reference.baseline.write_json(destination,{})
                return 2
            def bootstrap(run,archive,report,action):
                reference.baseline.write_json(report,{'violations':[]})
                return ['not-executed-old-bootstrap',action]
            def stage(run,archive,stage,*arguments):
                reference.baseline.write_json(archive/(stage+'.json'),{stage:{'time':1}})
                if stage=='icall':reference.baseline.write_json(archive/'icall-targets.json',{})
                return {'exit_code':0,'scope':'Mock dispatch fixture, not real old analysis'}
            with patch.object(reference,'validate_plan',return_value=(run,archive)),\
                 patch.object(reference.baseline,'inventory',return_value=[]),\
                 patch.object(reference.baseline,'git',return_value=''),\
                 patch.object(reference.baseline,'copy_run',side_effect=copy),\
                 patch.object(reference.baseline,'copy_bootstrap'),\
                 patch.object(reference.baseline,'bootstrap_command',side_effect=bootstrap),\
                 patch.object(reference.subprocess,'run',return_value=SimpleNamespace(returncode=0,stdout=json.dumps({'environment':{},'contract':proof['contract']}).encode(),stderr=b'')),\
                 patch.object(reference.baseline,'run_stage',side_effect=stage) as executed,\
                 patch.object(reference.baseline,'validate_run_root'),\
                 patch.object(reference.baseline,'verify_legacy_step') as integrity:
                self.assertEqual(reference.execute(args,output),0)
                args.icall_check=False;self.assertEqual(reference.execute(args,output),0)
                self.assertEqual([call.args[2] for call in executed.call_args_list],['icall','taint'])
                self.assertEqual([call.args[-1] for call in integrity.call_args_list],['parser','icall','taint'])
            self.assertEqual(reference.read(output/'taint.json')['memory_engine'],'legacy')
            self.assertEqual(reference.read(output/'taint.json')['engine'],'legacy-python-reference')
