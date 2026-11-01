"""Original SecurityCheck decisions remain separate from proof status."""
import unittest
from dataclasses import replace
from emtaint.analysis.bugfinder.legacy_policy import (WeakEvidence,LegacySecurityPolicy,
    SourceHandleEvidence,fake_file_sources)
from emtaint.procedures.legacy import legacy_format_parameters,lookup


class LegacyPolicyTests(unittest.TestCase):
    def evidence(self,**kwargs):
        return replace(WeakEvidence(0x100,0x80,'strcpy','copy',0x40,stack_address=0x7fffffff-32),**kwargs)

    def test_copy_bound_and_symbolic_filters_are_not_safety_proofs(self):
        policy=LegacySecurityPolicy()
        for constraints,expected in (((),True),((31,),False),((32,),True),((33,),True),((0,1),True),(('S',),False),(('Y',),True)):
            result=policy.classify(self.evidence(constraints=constraints))
            self.assertEqual(result.candidate,expected);self.assertFalse(result.confirmed)
        self.assertFalse(policy.classify(self.evidence(stack_address=0x80000000)).candidate)
        self.assertFalse(policy.classify(self.evidence(stack_address=None)).candidate)
        self.assertFalse(policy.classify(self.evidence(stack_address=None,memory_size=0)).candidate)
        self.assertTrue(policy.classify(self.evidence(stack_address=0x7fffffff)).candidate)

    def test_file_source_filter_requires_actual_handle_evidence_and_socket_overrides(self):
        handles=(SourceHandleEvidence((1,2),0x4000,8),SourceHandleEvidence((2,),0x4000,0x11),SourceHandleEvidence((3,),0,8))
        self.assertEqual(fake_file_sources(handles),frozenset((1,)))
        self.assertFalse(LegacySecurityPolicy(fake_sources=(0x40,)).classify(self.evidence(kind='command')).candidate)
        self.assertTrue(LegacySecurityPolicy().classify(self.evidence(kind='command',constraints=('S',))).candidate)

    def test_constraint_ids_and_guessed_length_match_old_policy(self):
        evidence=self.evidence(constraint_ids=('unresolved',))
        self.assertTrue(LegacySecurityPolicy(max_length=0).classify(evidence).candidate)
        self.assertFalse(LegacySecurityPolicy(max_length=31).classify(evidence).candidate)
        self.assertTrue(LegacySecurityPolicy(max_length=32).classify(evidence).candidate)
        self.assertEqual(LegacySecurityPolicy.guess_max_length((0,100,8192,9000,'S')),9000)

    def test_partial_concrete_bound_does_not_turn_unresolved_frontier_clean(self):
        evidence=self.evidence(constraints=(16,),constraint_ids=('unresolved-length-recipe-0',))
        decision=LegacySecurityPolicy().classify(evidence)
        self.assertTrue(decision.candidate)
        self.assertFalse(decision.confirmed)
        self.assertIn('Incomplete length frontier',decision.reason)
        resolved=replace(evidence,constraint_ids=())
        self.assertFalse(LegacySecurityPolicy().classify(resolved).candidate)

    def test_unmeasured_trace_counts_are_not_reported_as_zero(self):
        evidence=self.evidence()
        self.assertIsNone(evidence.indirect_depth);self.assertIsNone(evidence.propagation_level)
        self.assertIsNone(evidence.loop_count);self.assertEqual(evidence.inter_functions,())
        self.assertEqual(evidence.callsite_path,())

    def test_procedure_bounds_and_legacy_format_quirks_are_explicit(self):
        self.assertEqual(lookup('fread').lengths,(1,2));self.assertEqual(lookup('snprintf').lengths,(1,))
        for text,expected in ((b'%s %u %08s',('s','i','s')),(b'%*s %20[^ ]',('s',)),(b'%%s',('i','s')),(b'%ls',('i',))):
            self.assertEqual(legacy_format_parameters(text),expected)


if __name__=='__main__':unittest.main()
