import unittest
from unittest.mock import patch
from dataclasses import replace
import test_p7_demand as fixtures
from emtaint.ir.canonical import CIRBlock,DirectTarget
from emtaint.analysis.taint.demand import LegacyTaintDemand,TaintProcedureSummary,SinkRequirement,TaintDependency
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.analysis.taint.query_worklist import TaintQuery,run_queries


class QueryIsolationTests(unittest.TestCase):
    def test_known_source_is_bound_before_expensive_formal_alternatives(self):
        d=self.make(1);call=d.function.blocks[0].effects[1]
        d.active_sink=SinkRequirement(0x400,0x404,'system','command',(),(),'o1')
        def exhausted(*args,**kwargs):raise DemandLimit('Unresolved formal query',dimension='query')
        d.buffer=exhausted
        with self.assertRaises(DemandLimit):
            d.bind_dependencies((TaintDependency('argument',0),TaintDependency('source',0x900)),call,call.site.point.block,1)
        self.assertTrue(any(dep.kind=='source' and dep.value==0x900 for dep in d.partial_sources))

    def make(self,count,local=False):
        events=(('recv',(0,0x1000,16,0),True),('inner',(0x1000,),True))
        if local:events+=(('system',(0x1000,),True),)
        d,bid=fixtures.TaintDemandTests().make(events);effects=list(d.function.blocks[0].effects);fid=replace(bid.function,rva=0x400)
        effects[1]=replace(effects[1],target=DirectTarget(fid));function=replace(d.function,blocks=(CIRBlock(bid,tuple(effects)),))
        sinks=tuple(SinkRequirement(0x400,0x404+i*4,'system','command',(),(TaintDependency('argument',0),),'o1') for i in range(count))
        return LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,summaries={0x400:TaintProcedureSummary(0x400,sinks=sinks)})

    def test_local_callee_sink_limit_does_not_skip_later_callee_sinks(self):
        d=self.make(2);original=d.bind_sink
        def limited(sink,*args):
            if sink.site==0x404:raise DemandLimit('Injected local alternatives',dimension='alternatives')
            return original(sink,*args)
        d.bind_sink=limited;summary=d.analyze()
        self.assertTrue(any(sink.site==0x408 and any(dep.kind=='source' for dep in sink.dependencies) for sink in summary.sinks))

    def test_large_inherited_pool_does_not_starve_local_sink(self):
        d=self.make(257,local=True)
        def exhausted(*args):raise DemandLimit('Injected inherited worklist exhaustion')
        d.bind_sink=exhausted;summary=d.analyze()
        self.assertTrue(any(sink.function==0 and any(dep.kind=='source' for dep in sink.dependencies) for sink in summary.sinks))

    def test_large_inherited_pool_keeps_local_query_share(self):
        d=self.make(257,local=True)
        d.function_started=0;d.function_deadline=120;d.queries_remaining=300
        block=d.function.blocks[0]
        query=TaintQuery('local','call',block.id,2,block.effects[2])
        with patch('emtaint.analysis.taint.demand.time.monotonic',return_value=0):
            d.begin_query(query)
        self.assertGreater(d.inherited_sink_count,0)
        self.assertLess(d.query_step_limit-d.steps,d.max_steps//8)
        self.assertLess(d.query_clock_limit,d.function_deadline)

    def test_inherited_retry_runs_before_terminal_output_tail(self):
        d=self.make(1);block=d.function.blocks[0];call=block.effects[1]
        sink=d.summaries[0x400].sinks[0];attempts=0
        original_bind=d.bind_sink;original_execute=d.execute_query
        def bind(*args,**kwargs):
            nonlocal attempts
            attempts+=1
            if attempts==1:raise DemandLimit('Injected independent share',dimension='query')
            return original_bind(*args,**kwargs)
        def execute(query):
            if query.id=='terminal':raise DemandLimit('Injected function deadline')
            return original_execute(query)
        d.bind_sink=bind;d.execute_query=execute
        queries=(TaintQuery('inherited','sink',block.id,1,call,sink),
            TaintQuery('terminal','output',block.id,1,call,0))
        with self.assertRaises(DemandLimit):run_queries(d,queries)
        self.assertEqual(attempts,2)
        completed=[item for item in d.completed_sinks if item is not None]
        self.assertTrue(any(dep.kind=='source' for item in completed for dep in item.dependencies))

    def test_return_first_pass_can_warm_cache_before_inherited_retry(self):
        d=self.make(1);block=d.function.blocks[0];call=block.effects[1]
        sink=d.summaries[0x400].sinks[0];attempts=0;order=[]
        original_bind=d.bind_sink;original_execute=d.execute_query
        def bind(*args,**kwargs):
            nonlocal attempts
            attempts+=1;order.append('sink'+str(attempts))
            if attempts==1:raise DemandLimit('Injected independent share',dimension='query')
            return original_bind(*args,**kwargs)
        def execute(query):
            if query.id=='warm':order.append('warm');return
            if query.id=='terminal':order.append('terminal');raise DemandLimit('Injected function deadline')
            return original_execute(query)
        d.bind_sink=bind;d.execute_query=execute
        queries=(TaintQuery('inherited','sink',block.id,1,call,sink),
            TaintQuery('warm','return',block.id,1,call),
            TaintQuery('terminal','output',block.id,1,call,0))
        with self.assertRaises(DemandLimit):run_queries(d,queries)
        self.assertEqual(order, ['sink1','warm','sink2','terminal'])

    def test_over_cap_buffer_frontier_is_a_retry_checkpoint(self):
        d=self.make(1);block=d.function.blocks[0];call=block.effects[1]
        sink=d.summaries[0x400].sinks[0];seen=[]
        def execute(query):
            if not seen:
                d.partial_sources.update(TaintDependency('source',site,uncertain=True)
                    for site in range(d.max_dependencies+1))
                seen.append('first')
                raise DemandLimit('Injected independent share',dimension='query')
            seen.append(query.payload.dependencies)
            d.active_sink=query.payload
        d.execute_query=execute
        run_queries(d,(TaintQuery('inherited','sink',block.id,1,call,sink),))
        resumed=seen[1]
        self.assertEqual(sum(dep.kind=='source' for dep in resumed),d.max_dependencies+1)
        self.assertTrue(any(dep.kind=='unknown' and 'retry resumes length' in str(dep.value)
            for dep in resumed))
