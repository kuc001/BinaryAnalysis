import unittest
from dataclasses import replace
import test_p7_demand as fixtures
from emtaint.core.contracts import ValueRef,ValueType,Constant
from emtaint.ir.canonical import CIRBlock,ReadRegister,RegisterSlice,Compute,ValueOp,DirectTarget
from emtaint.analysis.taint.demand import LegacyTaintDemand


class DestinationTests(unittest.TestCase):
    def callee(self,offset):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,128,0),True),('strcpy',(0,0x1000),True)))
        pointer=ValueRef('destination',ValueType.bv(32));adjusted=ValueRef('adjusted',pointer.type)
        effects=d.function.blocks[0].effects
        body=(ReadRegister('o0',pointer,RegisterSlice('r1',0,32,32)),effects[0],
            Compute('o1',adjusted,ValueOp.ADD,(pointer,Constant(offset,pointer.type))),replace(effects[1],arguments=(adjusted,effects[1].arguments[1])))
        function=replace(d.function,values=(pointer,adjusted),blocks=(CIRBlock(bid,body),))
        return LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial).analyze()

    def test_argument_destination_is_bound_to_the_actual_caller_stack_extent(self):
        for offset,expected in ((0,64),(12,52)):
            summary=self.callee(offset)
            self.assertEqual(summary.sinks[0].offsets,())
            d,bid=fixtures.TaintDemandTests().make((('callee',(0,0x7fffffff-64),True),))
            effects=d.function.blocks[0].effects;fid=replace(bid.function,rva=0x400)
            function=replace(d.function,blocks=(CIRBlock(bid,(replace(effects[0],target=DirectTarget(fid)),)),))
            d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,summaries={0x400:replace(summary,function=0x400)})
            result=d.analyze()
            self.assertIn(expected,result.sinks[0].offsets)
            self.assertTrue(any(dep.kind=='source' for dep in result.sinks[0].dependencies))
