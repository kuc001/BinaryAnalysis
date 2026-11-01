"""Source alternatives use existing upper bounds; no invented sources/paths."""
import itertools
import unittest
from dataclasses import replace
import test_p7_demand as fixtures
from emtaint.analysis.taint.demand import TaintDependency
from emtaint.analysis.bugfinder.legacy_policy import LegacySecurityPolicy,WeakEvidence


class DependencySubsumptionTests(unittest.TestCase):
    def demand(self):return fixtures.TaintDemandTests().make((('system',(0x1000,),True),))[0]

    def test_existing_broader_source_bound_covers_narrower_alternative(self):
        d=self.demand();source=TaintDependency('source',123,uncertain=True)
        small=replace(source,constraints=(16,),path=(1,2))
        broad=replace(source,constraints=(32,),path=(3,4))
        self.assertEqual(d.union(((small,broad),)),(broad,))
        self.assertIn((small,broad),d.covered_sources)
        from emtaint.analysis.taint.evidence import summary_evidence
        from emtaint.analysis.taint.demand import TaintProcedureSummary
        evidence=summary_evidence(TaintProcedureSummary(0),d.covered_sources)
        self.assertEqual(evidence['covered_source_alternatives'][0]['covered']['constraints'],(16,))
        self.assertEqual(d.union(((small,source),)),(source,))

    def test_equal_source_paths_are_recorded_before_representative_collapse(self):
        d=self.demand();base=TaintDependency('source',123,constraints=(32,),uncertain=True)
        first=replace(base,path=(123,0x410));second=replace(base,path=(123,0x420))
        retained=d.union(((first,second),))
        self.assertEqual(retained,(first,))
        self.assertIn((second,first),d.covered_sources)

    def test_each_retained_member_is_an_input_and_distinct_lineage_is_preserved(self):
        d=self.demand();base=TaintDependency('source',123,uncertain=True)
        rows=tuple(replace(base,value=source,offset=offset,handles=handles,
            constraints=(bound,)) for source,offset,handles,bound in itertools.product(
                (123,124),(0,4), ((),(('file',8),),(('socket',8),)),(8,16,32)))
        actual=d.union((rows,))
        self.assertEqual(len(actual),12)
        self.assertTrue(set(actual)<=set(rows))
        self.assertEqual({(x.value,x.offset,x.handles) for x in actual},
            {(x.value,x.offset,x.handles) for x in rows})

    def test_incomparable_guards_recipes_and_symbolic_filters_remain_distinct(self):
        d=self.demand();base=TaintDependency('source',123,uncertain=True)
        rows=(replace(base,guards=('left',)),replace(base,guards=('right',)),
            replace(base,recipes=('left',)),replace(base,recipes=('right',)),
            replace(base,constraints=('S',)),replace(base,constraints=('Y',)))
        self.assertEqual(set(d.union((rows,))),set(rows))
        # Existing unguarded source covers a guarded copy with the same bound.
        self.assertEqual(d.union(((base,replace(base,guards=('left',))),)),(base,))

    def test_caller_numeric_bound_and_legacy_candidate_never_lose_an_alternative(self):
        d=self.demand();policy=LegacySecurityPolicy(max_length=8192)
        for bounds in itertools.combinations((None,2,4,8,16),3):
            rows=tuple(TaintDependency('source',123,constraints=() if bound is None else (bound,),uncertain=True) for bound in bounds)
            retained=d.union((rows,))
            for caller in ((),(3,),(9,)):
                for offset in range(1,20):
                    def candidate(dep):
                        constraints=d.constraints(dep.constraints,caller)
                        return policy.classify(WeakEvidence(4,0,'strcpy','copy',123,
                            stack_address=0x7fffffff-offset,constraints=constraints)).candidate
                    self.assertEqual(any(map(candidate,rows)),any(map(candidate,retained)))

    def test_dependency_budget_counts_nonredundant_facts(self):
        d=self.demand();base=TaintDependency('source',123,uncertain=True)
        rows=tuple(replace(base,constraints=(bound,)) for bound in range(2,302))
        self.assertEqual(d.union((rows,)),(replace(base,constraints=(301,)),))
        # Formal/global dependencies are not Source bounds and cannot be pruned.
        for kind in ('argument','global'):
            variants=tuple(TaintDependency(kind,0,constraints=(bound,)) for bound in (4,8))
            self.assertEqual(set(d.union((variants,))),set(variants))
