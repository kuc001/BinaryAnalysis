import hashlib
import json
from dataclasses import asdict
from pathlib import Path
import tempfile
import unittest
from test_p5_memory import engine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.taint.regions import RegionTaintTracker
from emtaint.analysis.taint.evidence import focused_snapshot
from emtaint.core.contracts import ValueType
from emtaint.results.memory_archive import archive_memory
from scripts.p7_evidence_verify import verify_source_links


class SourceLinkTests(unittest.TestCase):
    def run_case(self,change=None):
        base=Path(__file__).resolve().parents[1]/'.p7-work/test-source-links';base.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(dir=base) as temporary:
            phase=Path(temporary).resolve();phase.relative_to(base.resolve())
            e,root=engine();p=MemoryRuntimePort(e);tracker=RegionTaintTracker(p)
            loc=e.location(root,0,8,e.architecture.endian,'o0');truth=p.constant(True,ValueType.boolean(),'o0')
            value=p.symbol('real-source',ValueType.bv(8),'o0');state=p.write(e.initial,loc,value,truth,'o0').state
            binding=tracker.bind(state,loc,0x900,'o0',guard=truth)
            archive=phase/'source-memory';archive_memory(focused_snapshot(e.snapshot()),archive)
            digest=hashlib.sha256((archive/'manifest.json').read_bytes()).hexdigest();receipt=phase/'receipt.json'
            record={'source_site':0x900,'fact_id':binding.fact.id,'binding':json.loads(json.dumps(asdict(binding))),
                'archive':str(archive),'manifest_sha256':digest,'receipt':str(receipt)}
            receipt.write_text(json.dumps({'source_bindings':[record],'source_memory_evidence':{'manifest_sha256':digest}}))
            index=phase/'source-evidence-index.json';data={str(0x900):[record]}
            candidates=[{'evidence':{'source':0x900},'source_evidence_refs':[{'index':str(index),
                'source_site':0x900,'bindings':1}]}]
            if change:change(data,candidates)
            index.write_text(json.dumps(data));candidates[0]['source_evidence_refs'][0]['sha256']=hashlib.sha256(index.read_bytes()).hexdigest()
            candidate_path=phase/'candidates.json';candidate_path.write_text(json.dumps(candidates))
            return verify_source_links(phase,index,candidate_path)

    def test_actual_fact_receipt_and_candidate_links_are_verified(self):
        report=self.run_case();self.assertTrue(report['passed'])
        self.assertEqual((report['bindings'],report['linked_candidates']),(1,1))

    def test_wrong_source_or_fabricated_fact_cannot_pass(self):
        def wrong_source(index,candidates):candidates[0]['evidence']['source']=0xa00
        def fabricated(index,candidates):index[str(0x900)][0]['binding']['fact']['id']='invented-fact'
        for change in (wrong_source,fabricated):
            with self.assertRaises(ValueError):self.run_case(change)
