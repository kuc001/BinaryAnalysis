import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from scripts.p7_compare import compare


class ComparisonTests(unittest.TestCase):
    def run_case(self,actual=None,*,finalized=True,mapping=None,old_source=None,aggregated=False):
        base=Path(__file__).resolve().parents[1]/'.p7-work/test-comparison'
        base.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            Path(temporary).resolve().relative_to(base.resolve())
            root=Path(temporary);phase=root/'phase';golden=root/'golden';icall=root/'icall'
            for folder in (phase,golden,icall):folder.mkdir()
            def write(path,value):path.write_text(json.dumps(value),encoding='utf8')
            write(golden/'taint.json',{'taint_1':{'buffer_overflow':{},'command_exec':{'0x14':{'func':16,'name':'system'}}}})
            for path in (golden/'icall-targets.json',icall/'icall-targets.json'):write(path,{})
            sink={'function':16,'site':20,'name':'system','kind':'command','offsets':[],
                'dependencies':[{'kind':'source','value':40}]}
            result=phase/'round-001-function-0x10-result.json'
            write(result,{'summary':{'function':16,'pending':[],'sinks':[sink]}})
            if finalized:write(phase/'candidates.json',[] if actual is None else [actual])
            if aggregated:
                write(phase/'manifest.json',{'status':'may_fixed_point','coverage':'full-program','pending_functions':{}})
                write(phase/'requirements.json',{'evidence_format':'P7-evidence-v5','requirements':[sink]})
                result.write_text('deliberately not JSON: aggregate path must not read this receipt',encoding='utf8')
            identity=None
            trace=None
            if old_source is not None:
                (golden/'taint.log').write_text('Controlled original trace fixture',encoding='utf8')
                trace=root/'trace.json';write(trace,{'parser_errors':[],
                    'golden_sha256':hashlib.sha256((golden/'taint.json').read_bytes()).hexdigest(),
                    'log_sha256':hashlib.sha256((golden/'taint.log').read_bytes()).hexdigest(),
                    'rows':[{'function':16,'site':20,'name':'system','sources':[old_source],
                        'missing_raw_source':False,'raw_evidence':[{'source':old_source,'constraints':[]}]}]})
            if mapping is not None:
                identity=root/'site-map.json';write(identity,{'validated':mapping,
                    'golden_sha256':hashlib.sha256((golden/'taint.json').read_bytes()).hexdigest(),
                    'entries':[{'function':16,'legacy_site':20,'native_site':19,'name':'system','validated':True,'same_instruction':True}]})
            return compare(phase,golden,icall,site_map=identity,legacy_trace=trace)

    def test_same_site_with_wrong_function_or_procedure_does_not_match(self):
        for function,name in ((99,'system'),(16,'popen')):
            actual={'evidence':{'kind':'command','site':20,'function':function,'name':name,'source':40},'offset':None}
            report=self.run_case(actual)
            self.assertNotEqual(report['golden_finding_rows'][0]['status'],'candidate_present_evidence_review_required')
            self.assertTrue(report['additional_may_candidates'])

    def test_partial_analysis_is_not_reported_as_a_policy_difference(self):
        report=self.run_case(finalized=False)
        self.assertEqual(report['golden_finding_rows'][0]['status'],'analysis_not_finalized')

    def test_explicit_validated_site_identity_keeps_native_and_old_ids_separate(self):
        actual={'evidence':{'kind':'command','site':19,'function':16,'name':'system','source':40},'offset':None}
        report=self.run_case(actual,mapping=True);row=report['golden_finding_rows'][0]
        self.assertEqual((row['site'],row['native_site']),(20,19))
        self.assertEqual(row['status'],'candidate_present_evidence_review_required')
        self.assertFalse(report['additional_may_candidates'])
        with self.assertRaises(ValueError):self.run_case(actual,mapping=False)

    def test_same_site_and_offset_with_wrong_source_is_a_difference(self):
        actual={'evidence':{'kind':'command','site':20,'function':16,'name':'system','source':41},'offset':None}
        row=self.run_case(actual,old_source=40)['golden_finding_rows'][0]
        self.assertEqual(row['status'],'candidate_source_or_offset_difference')
        self.assertEqual(row['source_comparison']['missing_source_or_offsets'],[40])

    def test_source_match_still_requires_independent_guard_and_constraint_review(self):
        actual={'evidence':{'kind':'command','site':20,'function':16,'name':'system','source':40},'offset':None}
        row=self.run_case(actual,old_source=40)['golden_finding_rows'][0]
        self.assertEqual(row['status'],'candidate_present_evidence_review_required')
        self.assertFalse(row['source_comparison']['missing_source_or_offsets'])
        self.assertFalse(row['source_comparison']['reviewed'])

    def test_finalized_phase_uses_aggregate_evidence_without_loading_large_receipts(self):
        actual={'evidence':{'kind':'command','site':20,'function':16,'name':'system','source':40},'offset':None}
        report=self.run_case(actual,aggregated=True)
        self.assertTrue(report['analysis_complete'])
        self.assertEqual(report['completed_functions'],1)
        self.assertEqual(report['golden_finding_rows'][0]['status'],'candidate_present_evidence_review_required')
