import unittest
from dataclasses import replace
from emtaint.core import ContextId
from emtaint.analysis.taint.demand import TaintProcedureSummary,SinkRequirement,TaintDependency
from emtaint.analysis.taint.summary_join import SummaryAccumulator,semantic_equal


class SummaryJoinTests(unittest.TestCase):
    def test_exhausted_reanalysis_preserves_known_flow_with_same_cir(self):
        sink=SinkRequirement(16,20,'system','command',(),(TaintDependency('source',40),),'o0')
        first=TaintProcedureSummary(16,sinks=(sink,))
        partial=TaintProcedureSummary(16,pending=(('o1','deadline'),))
        state=SummaryAccumulator();state.update('body-a',first)
        result=state.update('body-a',partial)
        self.assertEqual(result.sinks,(sink,));self.assertEqual(result.pending,partial.pending)
        self.assertEqual(state.update('body-a',partial),result)

    def test_source_constraints_remain_distinct_and_merge_order_is_deterministic(self):
        dep=TaintDependency('source',40,constraints=(16,))
        sink=SinkRequirement(16,20,'strcpy','copy',(32,),(dep,),'o0')
        a=TaintProcedureSummary(16,sinks=(sink,))
        b=replace(a,sinks=(replace(sink,dependencies=(replace(dep,constraints=(128,)),)),))
        left=SummaryAccumulator();left.update('body',a);result=left.update('body',b)
        right=SummaryAccumulator();right.update('body',b)
        self.assertEqual(right.update('body',a),result)
        self.assertEqual({dep.constraints for dep in result.sinks[0].dependencies},{(16,),(128,)})

    def test_actual_cir_change_discards_previous_flows(self):
        state=SummaryAccumulator()
        state.update('old-body',TaintProcedureSummary(16,returns=(TaintDependency('source',40),)))
        changed=TaintProcedureSummary(16)
        self.assertEqual(state.update('new-body',changed),changed)

    def test_contexts_and_callee_revisions_do_not_merge_stale_flows(self):
        source=TaintProcedureSummary(16,returns=(TaintDependency('source',40),))
        empty=TaintProcedureSummary(16)
        first=ContextId((), 'caller-first')
        second=ContextId((), 'caller-second')
        state=SummaryAccumulator()
        state.update(('body','callee-v1'),source,context=first)
        self.assertEqual(state.update(('body','callee-v1'),empty,context=second),empty)
        self.assertEqual(state.update(('body','callee-v1'),empty,context=first).returns,source.returns)
        self.assertEqual(state.update(('body','callee-v2'),empty,context=first),empty)

    def test_deadline_location_changes_do_not_invalidate_unchanged_semantics(self):
        a=TaintProcedureSummary(16,pending=(('o1','deadline'),))
        b=replace(a,pending=(('o2','deadline'),))
        self.assertTrue(semantic_equal(a,b))
        self.assertFalse(semantic_equal(a,replace(a,pending=())))
