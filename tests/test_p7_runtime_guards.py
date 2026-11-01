import unittest
from dataclasses import replace
import test_p7_demand as fixtures
from emtaint.core import BlockId
from emtaint.core.contracts import ValueRef,ValueType,Constant
from emtaint.ir.canonical import CIRBlock,LoadEffect,Compute,ValueOp,BranchEffect
from emtaint.graph import ControlFlowGraph,FlowEdge,FlowKind
from emtaint.analysis.taint.demand import LegacyTaintDemand


class RuntimeGuardTests(unittest.TestCase):
    def guarded(self,writable):
        d,bid=fixtures.TaintDemandTests().make((('system',(0x1000,),True),))
        if not writable:
            d.port.engine.segments=tuple((a,b,c,4) for a,b,c,_ in d.port.engine.segments)
        value=ValueRef('flag',ValueType.bv(32));condition=ValueRef('flag-is-set',ValueType.boolean())
        yes=BlockId(bid.function,0x20);no=BlockId(bid.function,0x40)
        effects=(LoadEffect('o0',value,Constant(0x2000,ValueType.pointer(32)),32,d.port.engine.architecture.endian,Constant(True,ValueType.boolean())),
            Compute('o0',condition,ValueOp.EQ,(value,Constant(1,ValueType.bv(32)))),BranchEffect('o0',condition,yes,no))
        function=replace(d.function,values=(value,condition),blocks=(CIRBlock(bid,effects),CIRBlock(yes,()),CIRBlock(no,())))
        cfg=ControlFlowGraph(bid.function,frozenset((bid,yes,no)),frozenset((FlowEdge(bid,yes,FlowKind.TRUE),FlowEdge(bid,no,FlowKind.FALSE))),bid)
        return LegacyTaintDemand(function,d.port,cfg,d.demand.initial),bid,yes,no

    def test_writable_loader_snapshot_cannot_prune_a_runtime_taint_branch(self):
        d,bid,yes,no=self.guarded(True)
        reference=d.demand.value(d.function.blocks[0].effects[1].result)[0]
        self.assertIs(d.port.concrete(reference),False)  # Candidate snapshot remains available.
        location=d.location(d.port.constant(0x1000,ValueType.bv(32),'o0'),'o0')
        self.assertTrue(d.edge_policy(bid,yes,location)[0])
        self.assertTrue(d.edge_policy(bid,no,location)[0])

    def test_immutable_image_constant_still_prunes_an_impossible_branch(self):
        d,bid,yes,no=self.guarded(False)
        location=d.location(d.port.constant(0x1000,ValueType.bv(32),'o0'),'o0')
        self.assertFalse(d.edge_policy(bid,yes,location)[0])
        self.assertTrue(d.edge_policy(bid,no,location)[0])
