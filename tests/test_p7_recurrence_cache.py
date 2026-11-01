"""Repeated P7 demands at one immutable CFG cutoff share a loop remainder."""
import unittest

import test_p6_demand as fixtures
from emtaint.core.contracts import ValueRef,Constant
from emtaint.ir.canonical import Compute,ValueOp
from emtaint.analysis.taint.demand import ProcedureDemand


class RecurrenceCacheTests(unittest.TestCase):
    def test_nonaffine_loop_value_is_reused_at_the_same_cutoff(self):
        t=fixtures.t
        before=ValueRef('before',t);multiplied=ValueRef('multiplied',t)
        out=ValueRef('out',t)
        old,function,cfg=fixtures.DemandTests().make(((fixtures.put('r9',Constant(7,t)),),
            (fixtures.get('r9',before),Compute('o0',multiplied,ValueOp.MUL,(before,Constant(2,t))),fixtures.put('r9',multiplied)),
            (fixtures.get('r9',out),)),((0,1),(1,1),(1,2)))
        demand=ProcedureDemand(function,old.port,cfg,old.initial)
        block=function.blocks[2].id
        first=demand.register(block,0,'r9',32,0)
        first_cost=demand.steps
        second=demand.register(block,0,'r9',32,0)
        self.assertEqual(first,second)
        self.assertLess(demand.steps-first_cost,first_cost)
        self.assertGreater(demand.recurrence_cache_hits,0)


if __name__=='__main__':unittest.main()
