"""Prepared-copy recovery never reuses completed or modified analysis state."""
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
from scripts import p7_legacy_reference as reference


class PreparedResumeTests(unittest.TestCase):
    def run_case(self,mutate=None):
        base=reference.TARGET/'.p7-work/test-prepared-resume';base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            root=Path(temporary).resolve();root.relative_to(base.resolve())
            legacy=root/'legacy';run=root/'physical';archive=root/'archive';output=root/'output'
            for folder in (legacy,run,archive,output):folder.mkdir()
            for relative in (Path('main.py'),reference.baseline.REL_RESULT,reference.baseline.REL_META/'httpd_icall.json'):
                path=legacy/relative;path.parent.mkdir(parents=True,exist_ok=True);path.write_text('{}')
            before=reference.baseline.inventory(legacy)
            for record in before:
                path=run/record['path'];path.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(legacy/record['path'],path)
            bootstrap=reference.TARGET/'scripts/legacy_readonly_bootstrap.py';shutil.copy2(bootstrap,run/'_p0b_bootstrap.py')
            plan={'run_root':str(run),'archive_root':str(archive),'output':str(output),
                'binary_sha256':'fixture','bootstrap_sha256':reference.baseline.sha(bootstrap)}
            (archive/'file-inventory-before.json').write_text(json.dumps(before));(archive/'plan.json').write_text(json.dumps(plan))
            shutil.copy2(run/reference.baseline.REL_RESULT,archive/'preexisting.json')
            shutil.copy2(run/reference.baseline.REL_META/'httpd_icall.json',archive/'preexisting-icall-targets.json')
            if mutate:mutate(run,archive,output)
            with patch.object(reference.baseline,'LEGACY',legacy),patch.object(reference.baseline,'validate_run_root'):
                return reference.verify_prepared(run,archive,output,before,plan)

    def test_only_an_intact_unstarted_physical_copy_can_resume(self):
        self.assertEqual(self.run_case(),3)

    def test_completed_cache_modified_copy_and_snapshot_are_rejected(self):
        def started(run,archive,output):(archive/'icall.log').write_text('already started')
        def state(run,archive,output):(output/'legacy-state.json').write_text('{}')
        def cache(run,archive,output):(run/'.p0b-cache').mkdir()
        def modified(run,archive,output):(run/'main.py').write_text('changed')
        def extra(run,archive,output):(run/'unexpected.py').write_text('new')
        def snapshot(run,archive,output):(archive/'preexisting.json').write_text('changed')
        for mutate in (started,state,cache,modified,extra,snapshot):
            with self.subTest(case=mutate.__name__),self.assertRaises(ValueError):self.run_case(mutate)

    def test_selected_isolation_proof_matches_actual_current_bootstrap(self):
        proof=reference.read(reference.isolation_reference())
        reference.baseline.require_isolation(proof)
        self.assertTrue(proof['contract_equal'])
