import unittest
import test_p7_demand as fixtures


class QueryFairnessTests(unittest.TestCase):
    def test_inherited_callsites_interleave_without_moving_later_priority(self):
        from types import SimpleNamespace
        from emtaint.analysis.taint.query_worklist import TaintQuery,interleave_inherited_prefix

        def query(kind,origin):
            return TaintQuery(kind+origin,kind,None,0,SimpleNamespace(origin=origin))
        owner=SimpleNamespace(summaries={1:SimpleNamespace(sinks=(1,)),2:SimpleNamespace(sinks=(2,))},
            call_functions=lambda effect:(1,) if effect.origin=='A' else (2,) if effect.origin=='B' else ())
        original=(query('source','S'),query('call','A'),query('table','A'),query('sink','A'),
            query('call','B'),query('table','B'),query('sink','B'),query('call','local'))
        actual=interleave_inherited_prefix(owner,original)
        self.assertEqual([(item.kind,item.effect.origin) for item in actual],
            [('source','S'),('call','A'),('call','B'),('table','A'),('table','B'),
             ('sink','A'),('sink','B'),('call','local')])

        earlier=(query('source','S'),query('call','local'))+original[1:-1]
        actual=interleave_inherited_prefix(owner,earlier)
        self.assertEqual([(item.kind,item.effect.origin) for item in actual],
            [('source','S'),('call','local'),('call','A'),('call','B'),
             ('table','A'),('table','B'),('sink','A'),('sink','B')])

    def test_one_expensive_query_cannot_spend_all_work_before_later_local_sink(self):
        d,_=fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),
            ('system',(0x1000,),True),('system',(0x1000,),True)))
        d.max_steps=1000;buffer=d.buffer
        def busy(block,index,value,origin,**keywords):
            if origin=='o1':
                while True:d.tick()
            return buffer(block,index,value,origin,**keywords)
        d.buffer=busy;summary=d.analyze()
        first=next(s for s in summary.sinks if s.site==4)
        self.assertTrue(any(dep.kind=='unknown' for dep in first.dependencies))
        second=next(s for s in summary.sinks if s.site==8)
        self.assertTrue(any(dep.kind=='source' for dep in second.dependencies))
        self.assertTrue(summary.pending)
        self.assertLessEqual(d.steps,d.max_steps+1)

    def test_query_exhaustion_preserves_sources_already_observed(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),
            ('system',(0x1000,),True),('system',(0x1000,),True)))
        d.max_steps=1000;buffer=d.buffer
        def busy(block,index,value,origin,**keywords):
            result=buffer(block,index,value,origin,**keywords)
            if origin=='o1':
                while True:d.tick()
            return result
        d.buffer=busy;summary=d.analyze()
        for site in (4,8):
            sink=next(s for s in summary.sinks if s.site==site)
            self.assertTrue(any(dep.kind=='source' for dep in sink.dependencies))
        self.assertTrue(summary.pending)
