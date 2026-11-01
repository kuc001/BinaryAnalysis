import unittest
import test_p6_demand as fixtures
from test_p6_demand import get,put,t
from emtaint.core.contracts import Constant,ValueRef
from emtaint.analysis.taint.demand import ProcedureDemand


class ReachingCacheTests(unittest.TestCase):
    def make(self,cache=True):
        out=ValueRef('out',t)
        old,f,cfg=fixtures.DemandTests().make(((put('r4',Constant(99,t)),),
            (),(),(get('r4',out),)),((0,1),(1,2),(2,1),(2,3)))
        return ProcedureDemand(f,old.port,cfg,old.initial,cache_queries=cache),f

    def test_immutable_cfg_definition_query_is_shared_and_matches_uncached(self):
        cached,f=self.make();plain,_=self.make(False);block=f.blocks[-1].id
        expected=plain.reaching(block,1,'r4');first=cached.reaching(block,1,'r4');steps=cached.steps
        self.assertEqual(first,expected)
        self.assertEqual(cached.reaching(block,1,'r4'),expected)
        self.assertLessEqual(cached.steps-steps,2)
        self.assertEqual(first[0],frozenset(((f.blocks[0].id,1),)))

    def test_cached_definition_query_still_rejects_stale_scope(self):
        demand,f=self.make();block=f.blocks[-1].id;demand.reaching(block,1,'r4')
        def stale():raise RuntimeError('stale scope')
        demand.port.validate_current=stale
        with self.assertRaisesRegex(RuntimeError,'stale scope'):demand.reaching(block,1,'r4')
