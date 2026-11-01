import unittest
from dataclasses import replace
import test_p7_demand as fixtures
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from unittest.mock import patch


class QueryResourceTests(unittest.TestCase):
    def make(self):
        d,_=fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),
            ('system',(0x1000,),True),('system',(0x1000,),True)))
        return d

    def test_memory_worklist_share_leaves_work_for_later_sink_and_restores_observer(self):
        d=self.make();e=d.port.engine
        e.budgets=replace(e.budgets,worklist_iterations=1000);e.accounting.budgets=e.budgets
        original=d.buffer
        def expensive(block,index,value,origin,**kwargs):
            if origin=='o1':
                while True:e.accounting.charge('worklist_iterations')
            return original(block,index,value,origin,**kwargs)
        d.buffer=expensive;summary=d.analyze()
        later=next(s for s in summary.sinks if s.site==8)
        self.assertTrue(any(dep.kind=='source' for dep in later.dependencies))
        self.assertLessEqual(e.accounting.counts['worklist_iterations'],1000)
        self.assertIsNone(e.accounting.observer)

    def test_scalar_share_does_not_poison_argument_cache(self):
        d=self.make();call=d.function.blocks[0].effects[1]
        d.demand.query_scalar_limit=d.demand.steps
        with self.assertRaises(DemandLimit):d.argument(call,0)
        self.assertNotIn((call.origin,0),d.argument_cache)
        d.demand.query_scalar_limit=None
        self.assertEqual({d.port.concrete(value) for value in d.argument(call,0)},{0x1000})

    def test_completed_retry_removes_only_its_budget_frontier(self):
        d=self.make();d.max_steps=1000;original=d.buffer;attempts=0
        def first_only(block,index,value,origin,**kwargs):
            nonlocal attempts
            if origin=='o1':
                attempts+=1
                if attempts==1:
                    while True:d.tick()
            return original(block,index,value,origin,**kwargs)
        d.buffer=first_only;summary=d.analyze()
        self.assertGreaterEqual(attempts,2)
        self.assertFalse(summary.pending)
        failed=next(row for row in d.query_history if row['status']=='incomplete')
        self.assertEqual((failed['kind'],failed['origin']),('call','o1'))
        self.assertGreater(failed['taint_steps'],0)
        self.assertGreaterEqual(failed['scalar_steps'],0)
        self.assertGreaterEqual(failed['memory_work'],0)
        self.assertGreaterEqual(failed['seconds'],0)
        for site in (4,8):
            sink=next(s for s in summary.sinks if s.site==site)
            self.assertTrue(any(dep.kind=='source' for dep in sink.dependencies))
            self.assertFalse(any(dep.kind=='unknown' for dep in sink.dependencies))

    def test_whole_sink_can_finish_multiple_primitive_memory_queries_without_restarting(self):
        events=(('recv',(0,0x1000,16,0),True),('system',(0x1000,),True),('system',(0x1000,),True))
        d,_=fixtures.TaintDemandTests().make(events+(('ignored',(),True),)*500)
        accounting=d.port.engine.accounting;accounting.budgets=replace(accounting.budgets,worklist_iterations=2000000)
        original=d.buffer;attempts=0;primitive_limit=d.port.budget.max_steps
        def multiple_queries(block,index,value,origin,**kwargs):
            nonlocal attempts
            if origin=='o1':
                attempts+=1
                # Six separate definition/alias operations, each below the
                # primitive query cap, form one indivisible sink demand.
                for _ in range(6):
                    for step in range(2000):accounting.charge('worklist_iterations')
            return original(block,index,value,origin,**kwargs)
        d.buffer=multiple_queries;summary=d.analyze()
        first=next(sink for sink in summary.sinks if sink.site==4)
        self.assertTrue(any(dep.kind=='source' for dep in first.dependencies))
        self.assertEqual(attempts,1);self.assertEqual(d.port.budget.max_steps,primitive_limit)
        self.assertLess(accounting.counts['worklist_iterations'],2000000)

    def test_whole_sink_clock_is_not_the_timeout_of_one_primitive_query(self):
        d=self.make();d.function_started=0;d.function_deadline=120;d.queries_remaining=1000
        with patch('emtaint.analysis.taint.demand.time.monotonic',return_value=0) as clock:
            d.begin_query();clock.return_value=2
            d.check_query_clock()
        self.assertEqual(d.port.budget.timeout_ms,1000)

    def test_local_sink_call_gets_a_function_share_before_inherited_queries(self):
        from emtaint.analysis.taint.query_worklist import TaintQuery
        d=self.make();d.function_started=0;d.function_deadline=120;d.queries_remaining=90
        call=d.function.blocks[0].effects[1]
        query=TaintQuery('local','call',d.function.blocks[0].id,1,call)
        with patch('emtaint.analysis.taint.demand.time.monotonic',return_value=0):
            d.begin_query(query)
        self.assertGreaterEqual(d.query_clock_limit,30)

    def test_local_sink_call_can_use_remaining_function_budget(self):
        from emtaint.analysis.taint.query_worklist import TaintQuery
        d=self.make();d.function_started=0;d.function_deadline=120;d.queries_remaining=90
        call=d.function.blocks[0].effects[1]
        query=TaintQuery('local','call',d.function.blocks[0].id,1,call)
        with patch('emtaint.analysis.taint.demand.time.monotonic',return_value=0):
            d.begin_query(query)
        self.assertGreaterEqual(d.query_step_limit-d.steps,d.max_steps//8)
        self.assertGreaterEqual(d.demand.query_scalar_limit-d.demand.steps,d.demand.budget.steps//4)
        self.assertEqual(d.query_clock_limit,d.function_deadline)

    def test_global_limit_before_first_source_retains_the_active_unknown_sink(self):
        d=self.make();original=d.buffer
        def stopped(block,index,value,origin,**kwargs):
            if origin=='o1':raise DemandLimit('Function wall deadline; injected global stop')
            return original(block,index,value,origin,**kwargs)
        d.buffer=stopped;summary=d.analyze()
        first=next(sink for sink in summary.sinks if sink.site==4)
        self.assertTrue(any(dep.kind=='unknown' for dep in first.dependencies))
        self.assertFalse(any(dep.kind=='source' for dep in first.dependencies))

