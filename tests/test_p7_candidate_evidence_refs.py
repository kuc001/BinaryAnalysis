"""A candidate must retain every source requirement that led to its weak key."""
import unittest

from emtaint.analysis.bugfinder.candidate_evidence import (candidate_key, requirement_references,
    source_fact_references, merge_fact_references, CANDIDATE_REFS_FORMAT)
from emtaint.analysis.taint.demand import SinkRequirement, TaintDependency
from emtaint.analysis.taint.evidence import EvidenceEncoder


class CandidateEvidenceReferenceTests(unittest.TestCase):
    def test_additive_candidate_reference_schema_is_explicitly_versioned(self):
        self.assertEqual(CANDIDATE_REFS_FORMAT,'P7-candidate-refs-v2')

    def test_same_source_and_sink_keep_distinct_paths_and_guards(self):
        first=TaintDependency('source',0x300,path=(0x300,0x410),guards=(('a','eq32',1),))
        second=TaintDependency('source',0x300,path=(0x300,0x420),guards=(('b','ne32',0),))
        sink=SinkRequirement(0x100,0x120,'strcpy','copy',(64,),
            (first,second),'sink')
        key=candidate_key(sink,first,64)
        refs=requirement_references((sink,),{key})
        self.assertEqual(refs[key],((0,0),(0,1)))
        encoded=EvidenceEncoder().sink(sink)
        self.assertEqual([encoded['dependencies'][dependency]['path']
                          for requirement,dependency in refs[key]],
                         [(0x300,0x410),(0x300,0x420)])

    def test_same_site_in_different_function_or_procedure_stays_distinct(self):
        source=TaintDependency('source',0x300)
        first=SinkRequirement(0x100,0x120,'strcpy','copy',(64,),(source,),'sink-a')
        other_function=SinkRequirement(0x200,0x120,'strcpy','copy',(64,),(source,),'sink-b')
        other_procedure=SinkRequirement(0x100,0x120,'strcat','copy',(64,),(source,),'sink-c')
        key=candidate_key(first,source,64)
        refs=requirement_references((first,other_function,other_procedure),{key})
        self.assertEqual(refs[key],((0,0),))

    def test_source_fact_reference_prefers_the_projected_callsite(self):
        dependency=TaintDependency('source',0x300,path=(0x300,0x420))
        rows=({'source_site':0x300,'fact_id':'source','program_site':0x300},
              {'source_site':0x300,'fact_id':'caller-a','program_site':0x410},
              {'source_site':0x300,'fact_id':'caller-b-old','program_site':0x420,'function':1,'round':1},
              {'source_site':0x300,'fact_id':'caller-b','program_site':0x420,'function':1,'round':2})
        self.assertEqual([row['fact_id'] for row in source_fact_references(rows,dependency)],['caller-b'])
        merged=merge_fact_references(({'fact_id':'caller-a'},),({'fact_id':'caller-b'},{'fact_id':'caller-a'}))
        self.assertEqual({row['fact_id'] for row in merged},{'caller-a','caller-b'})

    def test_source_only_path_keeps_bucket_and_does_not_claim_exact_projection(self):
        dependency=TaintDependency('source',0x300,path=(0x300,))
        rows=({'source_site':0x300,'fact_id':'source','program_site':0x300},
              {'source_site':0x300,'fact_id':'caller','program_site':0x410})
        self.assertEqual({row['fact_id'] for row in source_fact_references(rows,dependency)},
                         {'source','caller'})


if __name__=='__main__':
    unittest.main()
