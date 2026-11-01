import unittest
from pathlib import Path
from scripts.p7_legacy_reference import plan_for,validate_plan,TARGET,MIGRATION


class LegacyPlanTests(unittest.TestCase):
    def test_preparation_only_describes_fresh_physical_paths(self):
        output=TARGET/'.p7-work/test-legacy-plan-output'
        plan=plan_for(output);run,archive=validate_plan(plan,output,'icall')
        self.assertFalse(run.exists());self.assertFalse(archive.exists())
        self.assertIn('separate approval',plan['authorization'])

    def test_old_repository_golden_and_foreign_output_paths_are_rejected(self):
        output=TARGET/'.p7-work/test-legacy-plan-output';plan=plan_for(output)
        for key,value in (('run_root',MIGRATION/'EmTaint'),
                          ('archive_root',MIGRATION/'baselines/rv130_1_0_3_44/20261028T051055Z-96d1c781'),
                          ('output',MIGRATION/'EmTaint/data')):
            with self.subTest(key=key),self.assertRaises(ValueError):
                validate_plan({**plan,key:str(value)},output,'icall')

    def test_changed_bootstrap_is_rejected_before_any_copy(self):
        output=TARGET/'.p7-work/test-legacy-plan-output';plan=plan_for(output)
        with self.assertRaisesRegex(ValueError,'Bootstrap changed'):
            validate_plan({**plan,'bootstrap_sha256':'0'*64},output,'icall')
