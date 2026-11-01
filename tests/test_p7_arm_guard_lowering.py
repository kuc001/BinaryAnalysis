"""Independent ARM HI flag-chain cases; no target address or solver shortcut."""
import unittest
from dataclasses import replace

from emtaint.core.contracts import Constant, ValueRef, ValueType
from emtaint.ir.canonical import Compute, ValueOp
from emtaint.analysis.taint.guards import arm_unsigned_hi,arm_zero_flag_equal
from emtaint.analysis.taint.guards import unit_product_arguments


class ArmUnsignedHiTests(unittest.TestCase):
    def chain(self, *, compare=ValueOp.ULT, subtraction_left=None, bits=32):
        word=ValueType.bv(bits);boolean=ValueType.boolean()
        left=ValueRef('input',word);right=Constant(77,word)
        other=ValueRef('other',word)
        zero=Constant(0,word);one=Constant(1,word)
        effects=[]

        def emit(op,args,result_type=word,params=()):
            result=ValueRef('v'+str(len(effects)),result_type)
            effects.append(Compute('guard-fixture',result,op,tuple(args),params))
            return result

        less=emit(compare,(left,right),boolean)
        greater_equal=emit(ValueOp.IF,(less,zero,one))
        difference=emit(ValueOp.SUB,(subtraction_left or left,right))
        equal=emit(ValueOp.EQ,(difference,zero),boolean)
        equal_word=emit(ValueOp.IF,(equal,one,zero))
        unequal=emit(ValueOp.XOR,(equal_word,one))
        greater=emit(ValueOp.AND,(greater_equal,unequal))
        extracted=emit(ValueOp.EXTRACT,(greater,),ValueType.bv(1),(0,0))
        condition=emit(ValueOp.EQ,(extracted,Constant(1,ValueType.bv(1))),boolean)
        return tuple(effects),condition,left,right,other

    def test_unsigned_true_and_false_edges_keep_width_and_direction(self):
        effects,condition,left,right,_=self.chain()
        guard=arm_unsigned_hi(effects,condition)
        self.assertEqual((guard.left,guard.right,guard.bits),(left,right,32))
        self.assertEqual(guard.relation(True),'ugt')
        self.assertEqual(guard.relation(False),'ule')

    def test_signed_or_mismatched_flag_chain_cannot_claim_unsigned_bound(self):
        signed,condition,_,_,_=self.chain(compare=ValueOp.SLT)
        self.assertIsNone(arm_unsigned_hi(signed,condition))
        mismatched,condition,_,_,_=self.chain(subtraction_left=ValueRef('other',ValueType.bv(32)))
        self.assertIsNone(arm_unsigned_hi(mismatched,condition))
        wider,condition,_,_,_=self.chain(bits=64)
        self.assertIsNone(arm_unsigned_hi(wider,condition))

    def test_unknown_or_partial_chain_is_not_a_guard_proof(self):
        effects,condition,_,_,_=self.chain()
        self.assertIsNone(arm_unsigned_hi(effects[:-2],condition))
        changed=list(effects)
        changed[-2]=replace(changed[-2],params=(1,1))
        self.assertIsNone(arm_unsigned_hi(tuple(changed),condition))


class ArmZeroFlagTests(unittest.TestCase):
    def chain(self, *, result_if_true=1, right_bits=32):
        word=ValueType.bv(32);boolean=ValueType.boolean()
        left=ValueRef('loaded-pointee',word)
        right=Constant(1,ValueType.bv(right_bits))
        zero=Constant(0,word);one=Constant(1,word)
        difference=ValueRef('difference',word)
        equal=ValueRef('equal',boolean)
        flag=ValueRef('flag',word)
        low=ValueRef('low',ValueType.bv(1))
        condition=ValueRef('condition',boolean)
        effects=(Compute('guard-fixture',difference,ValueOp.SUB,(left,right)),
            Compute('guard-fixture',equal,ValueOp.EQ,(difference,zero)),
            Compute('guard-fixture',flag,ValueOp.IF,(equal,Constant(result_if_true,word),zero)),
            Compute('guard-fixture',low,ValueOp.EXTRACT,(flag,),(0,0)),
            Compute('guard-fixture',condition,ValueOp.EQ,(low,Constant(1,ValueType.bv(1)))))
        return effects,condition,left,right

    def test_equal_one_success_edge_and_inequality_failure_edge(self):
        effects,condition,left,right=self.chain()
        guard=arm_zero_flag_equal(effects,condition)
        self.assertEqual((guard.left,guard.right,guard.bits),(left,right,32))
        self.assertEqual((guard.relation(True),guard.relation(False)),('eq','ne'))

    def test_wrong_flag_polarity_or_incomplete_chain_is_unknown(self):
        effects,condition,_,_=self.chain(result_if_true=0)
        self.assertIsNone(arm_zero_flag_equal(effects,condition))
        effects,condition,_,_=self.chain()
        self.assertIsNone(arm_zero_flag_equal(effects[:-2],condition))


class ArmPathGuardTests(unittest.TestCase):
    def test_resolved_jump_keeps_both_source_path_guards_as_may_evidence(self):
        from emtaint.core import BlockId,CallSiteId,ProgramPoint
        from emtaint.ir.canonical import CIRBlock,CallEffect,ExternalTarget,BranchEffect,JumpEffect
        from emtaint.graph import ControlFlowGraph,FlowEdge,FlowKind
        from emtaint.analysis.taint.demand import LegacyTaintDemand
        from emtaint.procedures.legacy import lookup
        import test_p7_demand as fixtures

        old,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),))
        entry=bid;skip=BlockId(bid.function,0x10);high=BlockId(bid.function,0x20)
        through=BlockId(bid.function,0x30);source_block=BlockId(bid.function,0x40)
        exit_block=BlockId(bid.function,0x50)
        equal,equal_condition,_,_=ArmZeroFlagTests().chain()
        high_effects,high_condition,_,_,_=ArmUnsignedHiTests().chain()
        call=replace(old.function.blocks[0].effects[0],
            site=CallSiteId(ProgramPoint(source_block,0,source_block.rva)))
        blocks=(CIRBlock(entry,equal+(BranchEffect('equal-edge',equal_condition,high,skip),)),
            CIRBlock(skip,(JumpEffect('literal-jump',exit_block),)),
            CIRBlock(high,high_effects+(BranchEffect('high-edge',high_condition,exit_block,through),)),
            CIRBlock(through,(JumpEffect('to-source',source_block),)),
            CIRBlock(source_block,(call,)),CIRBlock(exit_block,()))
        refs={value.id:value for block in blocks for effect in block.effects
            if isinstance(effect,Compute) for value in (effect.result,)+effect.args
            if isinstance(value,ValueRef)}
        function=replace(old.function,values=tuple(refs.values()),blocks=blocks)
        edges=frozenset((FlowEdge(entry,high,FlowKind.TRUE),FlowEdge(entry,skip,FlowKind.FALSE),
            FlowEdge(skip,exit_block,FlowKind.JUMP),FlowEdge(skip,high,FlowKind.UNKNOWN),
            FlowEdge(high,exit_block,FlowKind.TRUE),FlowEdge(high,through,FlowKind.FALSE),
            FlowEdge(through,source_block,FlowKind.JUMP)))
        cfg=ControlFlowGraph(bid.function,frozenset(block.id for block in blocks),edges,entry)
        demand=LegacyTaintDemand(function,old.port,cfg,old.demand.initial)
        self.assertEqual(set(demand.path_guards(call)),
            {('equal-edge','eq32',1),('high-edge','ule32',77)})
        location=demand.location(demand.port.constant(0x1000,ValueType.pointer(32),'source'),call.origin)
        dependency=demand.source(call,location,lookup('recv'))
        self.assertEqual(set(dependency.guards),set(demand.path_guards(call)))
        self.assertTrue(dependency.uncertain)
        self.assertTrue(any('Known-CIR path guard' in note for fact in demand.port.engine.facts
            for note in fact.provenance))

        unknown_blocks=blocks[:1]+(CIRBlock(skip,()),)+blocks[2:]
        incomplete=LegacyTaintDemand(replace(function,blocks=unknown_blocks),old.port,cfg,old.demand.initial)
        self.assertNotIn(('equal-edge','eq32',1),incomplete.path_guards(call))

        joined=ControlFlowGraph(bid.function,cfg.nodes,
            cfg.edges|frozenset((FlowEdge(exit_block,source_block,FlowKind.JUMP),)),entry)
        after_join=LegacyTaintDemand(function,old.port,joined,old.demand.initial)
        self.assertEqual(after_join.path_guards(call),())


class GuardedLengthTests(unittest.TestCase):
    def recipe(self, *, bits=32, operation='mul', uses=(1, 2)):
        from emtaint.analysis.framework.summaries import ProcedureRecipe, SummaryNode

        word=ValueType.bv(bits)
        nodes=(SummaryNode(word,'constant',value=1),
            SummaryNode(word,'argument',value=1),
            SummaryNode(word,'mul',(0,1)),
            SummaryNode(word,'argument',value=2),
            SummaryNode(word,operation,(2,3)))
        return ProcedureRecipe(None,nodes,(4,),(),uses,(),('*',),True)

    def test_only_exact_32_bit_unit_product_has_two_factor_slots(self):
        recipe=self.recipe()
        self.assertEqual(unit_product_arguments(recipe),(1,2))
        self.assertIsNone(unit_product_arguments(self.recipe(bits=64)))
        self.assertIsNone(unit_product_arguments(self.recipe(operation='add')))
        self.assertIsNone(unit_product_arguments(self.recipe(uses=(1,3))))
        self.assertIsNone(unit_product_arguments(replace(recipe,returns=(3,))))

    def test_length_bound_requires_both_guard_operands_to_match_same_call(self):
        from types import SimpleNamespace
        from emtaint.analysis.taint.demand import LegacyTaintDemand,ConstraintRecipe
        import test_p7_demand as fixtures

        original,block=fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),))
        demand=LegacyTaintDemand(original.function,original.port,original.cfg,original.demand.initial)
        word=ValueType.bv(32)
        refs=tuple(ValueRef(name,word) for name in ('arg0','arg1','arg2','equal','upper'))
        call=SimpleNamespace(origin='call',arguments=refs[:3])
        a=demand.port.symbol('factor-a',word,'fixture')
        b=demand.port.symbol('factor-b',word,'fixture')
        c=demand.port.symbol('unrelated',word,'fixture')
        mapped={refs[1]:a,refs[2]:b,refs[3]:a,refs[4]:b}
        demand.demand.value=lambda reference:(mapped[reference],)
        demand.path_guard_cache['call']=(('eq','eq32',1),('upper','ule32',77))
        demand.path_guard_operands['call']=(('eq','eq32',1,refs[3]),('upper','ule32',77,refs[4]))
        wrapped=(ConstraintRecipe.wrap(self.recipe()),)
        self.assertEqual(demand.guarded_length_guards(call,wrapped),(('call','length-ule32',77),))
        mapped[refs[4]]=c
        demand.guarded_length_cache.clear()
        self.assertEqual(demand.guarded_length_guards(call,wrapped),())
        mapped[refs[4]]=b
        demand.path_guard_operands['call']=(('eq','eq32',1,refs[3]),('upper','ult32',77,refs[4]))
        demand.guarded_length_cache.clear()
        self.assertEqual(demand.guarded_length_guards(call,wrapped),())
        demand.path_guard_operands['call']=(('eq','eq32',1,refs[3]),('upper','ule32',77,refs[4]))
        mapped[refs[4]]=demand.port.symbol('wide',ValueType.bv(64),'fixture')
        demand.guarded_length_cache.clear()
        self.assertEqual(demand.guarded_length_guards(call,wrapped),())
