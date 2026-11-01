import json
import unittest
from dataclasses import replace
from pathlib import Path
from test_p3_contracts import fixture
from emtaint.core.contracts import ValueType
from emtaint.analysis.framework.summaries import ProcedureRecipe,SummaryNode
from emtaint.analysis.taint.demand import ConstraintRecipe,TaintDependency,TaintProcedureSummary
from emtaint.analysis.taint.evidence import summary_evidence
from emtaint.orchestration.taint_program import summary_receipt_paths


class EvidenceTests(unittest.TestCase):
    def test_identical_raw_summary_reuses_final_receipt_without_losing_pending_details(self):
        receipt=Path('round-001-function-0x10')
        raw=TaintProcedureSummary(16,pending=('first diagnostic',))
        same=TaintProcedureSummary(16,pending=('first diagnostic',))
        changed=TaintProcedureSummary(16,pending=('different diagnostic',))
        raw_path,result_path=summary_receipt_paths(receipt,raw,same)
        self.assertEqual(raw_path,result_path)
        raw_path,result_path=summary_receipt_paths(receipt,raw,changed)
        self.assertNotEqual(raw_path,result_path)
        self.assertTrue(raw_path.name.endswith('-raw-summary.json'))
        self.assertTrue(result_path.name.endswith('-result.json'))

    def test_shared_constraint_recipe_has_one_payload_and_no_foreign_sse_id(self):
        _,fid,*_=fixture()
        recipe=ProcedureRecipe(fid,(SummaryNode(ValueType.bv(32),'argument',value=2),),(0,),(),(2,),('actual Cons recipe',),())
        shared=ConstraintRecipe.wrap(recipe)
        first=TaintDependency('source',0x100,recipes=(shared,));second=replace(first,value=0x200)
        summary=TaintProcedureSummary(0x80,returns=(first,),outputs=((0,(first,second)),))
        encoded=summary_evidence(summary)
        self.assertEqual(len(encoded['constraint_recipes']),1)
        self.assertEqual(encoded['summary']['returns'][0]['recipes'],[shared.key])
        self.assertEqual(encoded['summary']['outputs'][0][1][1]['recipes'],[shared.key])
        self.assertEqual(shared,ConstraintRecipe.wrap(recipe))
        text=json.dumps(encoded)
        self.assertNotIn('SymbolicExprId',text)
        self.assertEqual(encoded['evidence_format'],'P7-evidence-v5')

    def test_focused_source_archive_is_closed_and_uses_existing_wire_records(self):
        import uuid
        from pathlib import Path
        from test_p5_memory import engine
        from emtaint.compat.memory_runtime import MemoryRuntimePort
        from emtaint.analysis.taint.regions import RegionTaintTracker
        from emtaint.analysis.taint.evidence import focused_snapshot
        from emtaint.memory.engine import PythonMemoryEngine
        from emtaint.ir.canonical.wire import dumps,loads
        from emtaint.results.memory_archive import archive_memory,verify_archive
        e,root=engine();p=MemoryRuntimePort(e)
        loc=e.location(root,0,8,e.architecture.endian,'o0')
        guard=p.symbol('source-guard',ValueType.boolean(),'o0');byte=p.symbol('input',ValueType.bv(8),'o0')
        state=p.write(e.initial,loc,byte,guard,'o0').state
        RegionTaintTracker(p).bind(state,loc,0x900,'o0',guard=guard)
        unused=p.symbol('unrelated-expression',ValueType.bv(32),'o0')
        original=e.snapshot();focused=focused_snapshot(original)
        self.assertNotIn(unused,{node.id for node in focused.expressions})
        restored=PythonMemoryEngine.from_snapshot(loads(dumps(focused)))
        self.assertEqual(restored.facts,e.facts)
        self.assertIn(state,restored.versions)
        path=Path(__file__).resolve().parents[1]/'.p7-work'/('test-source-evidence-'+uuid.uuid4().hex)
        manifest=archive_memory(focused,path)
        self.assertTrue(verify_archive(path))
        self.assertEqual(manifest['groups']['taint_facts']['records'],1)
