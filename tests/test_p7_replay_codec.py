import unittest
import json
from dataclasses import replace
from test_p3_contracts import fixture
from emtaint.core.contracts import ValueType
from emtaint.analysis.framework.summaries import ProcedureRecipe,SummaryNode
from emtaint.analysis.taint.demand import (ConstraintRecipe,TaintDependency,TaintProcedureSummary,
    SinkRequirement,BufferDestination,DeferredFormatArgument)
from emtaint.analysis.taint.tables import TableRoot
from emtaint.analysis.taint.global_outputs import GlobalTaintOutput
from emtaint.core import Endian
from emtaint.analysis.taint.evidence import summary_evidence
from scripts.p7_replay_codec import decode


class ReplayCodecTests(unittest.TestCase):
    def evidence(self):
        binary,fid,*_=fixture()
        value=ProcedureRecipe(fid,(SummaryNode(ValueType.bv(32),'argument',value=2),),(0,),(),(2,),('Source bound',),())
        dep=TaintDependency('source',0x900,recipes=(ConstraintRecipe.wrap(value),))
        root=TableRoot(binary.sha256,'global',0x2000)
        sink=SinkRequirement(0,4,'strcpy','copy',(),(dep,),'o0',destinations=(BufferDestination('argument',1,12),))
        summary=TaintProcedureSummary(0,returns=(dep,),sinks=(sink,),tables=((root,(dep,)),))
        return summary,json.loads(json.dumps(summary_evidence(summary)))

    def test_private_summary_roundtrip_preserves_recipes_roots_and_destinations(self):
        import json
        summary,value=self.evidence()
        self.assertEqual(decode(json.loads(json.dumps(value))),summary)

    def test_v5_roundtrip_preserves_deferred_format_selector(self):
        nested=TaintDependency('argument',2,constraints=(32,))
        dependency=TaintDependency('format_argument',DeferredFormatArgument(1,0,nested),
            uncertain=True,unresolved_constraints=True)
        summary=TaintProcedureSummary(0,outputs=((0,(dependency,)),))
        payload=json.loads(json.dumps(summary_evidence(summary)))
        self.assertEqual(payload['evidence_format'],'P7-evidence-v5')
        self.assertEqual(decode(payload),summary)

    def test_tampered_recipe_and_unknown_fields_are_rejected(self):
        _,value=self.evidence();key=next(iter(value['constraint_recipes']))
        value['constraint_recipes'][key]['nodes'][0]['value']=3
        with self.assertRaisesRegex(ValueError,'hash mismatch'):decode(value)
        _,value=self.evidence();value['summary']['extra']='silently discarded'
        with self.assertRaisesRegex(ValueError,'Unexpected'):decode(value)

    def test_v3_separates_null_clean_and_tainted_scalar_returns(self):
        dep=TaintDependency('source',0x900,constraint_type=4)
        sink=SinkRequirement(0,4,'strncpy','copy',(32,),(dep,),'o0',weak_kind='copy_length',length_dependencies=(dep,))
        for scalar in (None,(),(TaintDependency('scalar_argument',2),)):
            summary=TaintProcedureSummary(0,sinks=(sink,),scalar_returns=scalar)
            self.assertEqual(decode(json.loads(json.dumps(summary_evidence(summary)))),summary)

    def test_old_v1_v2_bounded_evidence_is_unknown_not_a_clean_length(self):
        for version in ('P7-evidence-v1','P7-evidence-v2'):
            summary=TaintProcedureSummary(0,sinks=(SinkRequirement(0,4,'strncpy','copy',(32,),(), 'o0'),))
            payload=json.loads(json.dumps(summary_evidence(summary)));payload['evidence_format']=version
            payload['summary'].pop('scalar_returns')
            for sink in payload['summary']['sinks']:
                sink.pop('weak_kind');sink.pop('length_dependencies')
                if version=='P7-evidence-v1':sink.pop('destinations')
            result=decode(payload)
            self.assertIsNone(result.scalar_returns)
            self.assertEqual(result.sinks[0].weak_kind,'copy_length')
            self.assertTrue(any(dep.kind=='unknown' for dep in result.sinks[0].length_dependencies))

    def test_v4_global_outputs_roundtrip_and_v3_missing_mode_is_unknown(self):
        dep=TaintDependency('source',0x900)
        output=GlobalTaintOutput(0x2000,32,Endian.BIG,1,'o0',(dep,))
        for values in (None,(),(output,)):
            summary=TaintProcedureSummary(0,global_outputs=values)
            payload=json.loads(json.dumps(summary_evidence(summary)))
            self.assertEqual(decode(payload),summary)
        payload['evidence_format']='P7-evidence-v3';payload['summary'].pop('global_outputs')
        self.assertIsNone(decode(payload).global_outputs)

    def test_global_geometry_and_missing_v4_fields_are_rejected(self):
        summary=TaintProcedureSummary(0,global_outputs=(GlobalTaintOutput(0x2000,8,Endian.LITTLE,1,'o0'),))
        for field,bad in (('address',-1),('width_bits',7),('endian','host'),('span',0)):
            payload=json.loads(json.dumps(summary_evidence(summary)));payload['summary']['global_outputs'][0][field]=bad
            with self.assertRaises(ValueError):decode(payload)
        payload=json.loads(json.dumps(summary_evidence(summary)));payload['summary'].pop('global_outputs')
        with self.assertRaises(ValueError):decode(payload)
