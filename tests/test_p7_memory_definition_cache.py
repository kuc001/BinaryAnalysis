import unittest
from unittest.mock import patch
from dataclasses import replace
import test_p6_demand as fixtures
from test_p6_demand import t,ptr,truth
from test_p6_demand import get,put
from emtaint.core import Endian
from emtaint.core.contracts import Constant,ValueRef
from emtaint.ir.canonical import StoreEffect,LoadEffect,Compute,UnknownEffect,ValueOp
from emtaint.analysis.taint.demand import ProcedureDemand
from emtaint.analysis.dataflow.legacy_demand import ArgumentRead
from emtaint.memory.abstract_heap import ObjectCardinality


class DefinitionCacheTests(unittest.TestCase):
    def test_original_p6_transfer_cases_also_hold_for_the_p7_adapter(self):
        names=unittest.defaultTestLoader.getTestCaseNames(fixtures.DemandTests)
        with patch.object(fixtures,'LegacyDemand',ProcedureDemand):
            for name in names:
                with self.subTest(original_case=name):
                    getattr(fixtures.DemandTests(name),name)()

    def make(self):
        out=ValueRef('out',t)
        old,f,cfg=fixtures.DemandTests().make(((StoreEffect('o0',Constant(0x1000,ptr),Constant(0x3000,t),32,Endian.LITTLE,truth),),
            (),(),(LoadEffect('o0',out,Constant(0x1000,ptr),32,Endian.LITTLE,truth),)),((0,1),(1,2),(2,3)))
        d=ProcedureDemand(f,old.port,cfg,old.initial);e=d.port.engine
        loc=e.location(*e.address(0x1000),32,Endian.LITTLE,'o0')
        return d,f,loc,ArgumentRead(32,Endian.LITTLE,'o0')

    def test_definition_selection_reuses_immutable_versions_without_collapsing_read_addresses(self):
        d,f,loc,load=self.make();p=d.port
        left=p.addressed_location(loc,p.constant(0x1000,t,'o0'))
        right=p.addressed_location(loc,p.symbol('same-proven-region',t,'o0'))
        self.assertNotEqual(left.id,right.id)
        first=d.memory_definitions(f.blocks[-1].id,0,left,load,set(),0)
        steps=d.steps;writes=p.calls['write'];versions=len(p.engine.versions)
        second=d.memory_definitions(f.blocks[-1].id,0,right,load,set(),0)
        self.assertEqual(first,second)
        self.assertEqual({p.concrete(v) for v in second[0]},{0x3000})
        self.assertTrue(second[1]);self.assertLessEqual(d.steps-steps,1)
        self.assertEqual(p.calls['write'],writes);self.assertEqual(len(p.engine.versions),versions)

    def test_offset_width_and_object_cardinality_are_part_of_the_definition_identity(self):
        d,f,loc,load=self.make();block=f.blocks[-1].id
        self.assertTrue(d.memory_definitions(block,0,loc,load,set(),0)[1])
        e=d.port.engine;other=e.location(*e.address(0x1004),32,Endian.LITTLE,'o0')
        values,killed=d.memory_definitions(block,0,other,load,set(),0)
        self.assertEqual(values,());self.assertFalse(killed)
        fact=e.object_facts[loc.object_id]
        e.object_facts[loc.object_id]=replace(fact,cardinality=ObjectCardinality.SUMMARY)
        values,killed=d.memory_definitions(block,0,loc,load,set(),0)
        self.assertFalse(killed);self.assertTrue(values)
        self.assertTrue(all(d.port.guard_concrete(value) is None for value in values))

    def test_frontier_reuse_keeps_each_read_origin_and_address_identity(self):
        d,f,loc,load=self.make();p=d.port;e=p.engine;block=f.blocks[-1].id
        e.origins+= (replace(e.origins[0],id='other-read'),)
        d.memory_definitions(block,0,loc,load,set(),0);steps=d.steps
        other=e.location(*e.address(0x1000),32,Endian.LITTLE,'other-read')
        other=p.addressed_location(other,p.symbol('other-address-demand',t,'other-read'))
        result=d.memory_definitions(block,0,other,ArgumentRead(32,Endian.LITTLE,'other-read'),set(),0)
        self.assertTrue(result[1]);self.assertEqual({p.concrete(v) for v in result[0]},{0x3000})
        self.assertLessEqual(d.steps-steps,2)
        original={read.location for read in e.reads if read.origin=='o0'}
        actual={read.location for read in e.reads if read.origin=='other-read'}
        self.assertTrue(actual);self.assertTrue(actual.isdisjoint(original))
        self.assertTrue(all(e.locations[location].origin=='other-read' for location in actual))

    def test_unknown_object_projection_matches_original_for_cycles_false_stores_and_cutoffs(self):
        for false_guard in (False,True):
            for cyclic in (False,True):
                for index in (0,1):
                    with self.subTest(false_guard=false_guard,cyclic=cyclic,index=index):
                        store=StoreEffect('o0',Constant(0x1000,ptr),Constant(77,t),32,Endian.LITTLE,
                            Constant(not false_guard,truth.type))
                        old,f,cfg=fixtures.DemandTests().make(((store,),()),
                            ((0,1),(1,0)) if cyclic else ((0,1),))
                        d=ProcedureDemand(f,old.port,cfg,old.initial);e=d.port.engine
                        location=e.location(None,None,32,Endian.LITTLE,'o0');load=ArgumentRead(32,Endian.LITTLE,'o0')
                        expected=old.memory_definitions(f.blocks[0].id,index,location,load,set(),0)
                        actual=d.memory_definitions(f.blocks[0].id,index,location,load,set(),0)
                        self.assertEqual(actual,expected);self.assertFalse(actual[1])
                        if actual[0]:self.assertTrue(all(d.port.guard_concrete(value) is None for value in actual[0]))
                        steps=d.steps
                        other=e.location(None,None,8,Endian.LITTLE,'o0')
                        d.memory_definitions(f.blocks[1].id,0,other,ArgumentRead(8,Endian.LITTLE,'o0'),set(),0)
                        self.assertLessEqual(d.steps-steps,2)

    def test_global_projection_does_not_skip_a_possible_must_store(self):
        pointer=ValueRef('unknown-pointer',ptr)
        effects=(StoreEffect('o0',Constant(0x1000,ptr),Constant(77,t),32,Endian.LITTLE,truth),
            get('r4',pointer),StoreEffect('o0',pointer,Constant(88,t),32,Endian.LITTLE,truth))
        old,f,cfg=fixtures.DemandTests().make((effects,))
        demand=ProcedureDemand(f,old.port,cfg,old.initial);e=demand.port.engine
        for address in (0x1000,0x1004):
            with self.subTest(address=hex(address)):
                location=e.location(*e.address(address),32,Endian.LITTLE,'o0')
                load=ArgumentRead(32,Endian.LITTLE,'o0')
                expected=old.memory_definitions(f.entry,3,location,load,set(),0)
                actual=demand.memory_definitions(f.entry,3,location,load,set(),0)
                self.assertEqual(actual,expected)
                self.assertEqual(actual[1],address==0x1000)
                if address==0x1000:self.assertIn(77,{demand.port.guard_concrete(value) for value in actual[0]})

    def test_copied_constant_sp_offsets_do_not_create_false_may_alias(self):
        sp=ValueRef('stack-pointer',t)
        copied_sp=ValueRef('copied-stack-pointer',t)
        frame=ValueRef('frame-register',t)
        near=ValueRef('near-offset',t);far=ValueRef('far-offset',t)
        near_addr=ValueRef('near-address',t);far_addr=ValueRef('far-address',t)
        near_store=ValueRef('near-store-address',ptr);far_store=ValueRef('far-store-address',ptr)
        effects=(
            get('sp',sp),
            Compute('o0',copied_sp,ValueOp.COPY,(sp,)),
            put('r3',copied_sp),
            get('r3',frame),
            Compute('o0',near,ValueOp.COPY,(Constant(32,t),)),
            Compute('o0',near_addr,ValueOp.SUB,(frame,near)),
            Compute('o0',near_store,ValueOp.ADD,(Constant(0,ptr),near_addr)),
            StoreEffect('o0',near_store,Constant(77,t),32,Endian.LITTLE,truth),
            Compute('o0',far,ValueOp.COPY,(Constant(36,t),)),
            Compute('o0',far_addr,ValueOp.SUB,(frame,far)),
            Compute('o0',far_store,ValueOp.ADD,(Constant(0,ptr),far_addr)),
            StoreEffect('o0',far_store,Constant(88,t),32,Endian.LITTLE,truth),
        )
        old,function,cfg=fixtures.DemandTests().make((effects,))
        demand=ProcedureDemand(function,old.port,cfg,old.initial)
        engine=demand.port.engine
        stack_root=dict(old.initial.addresses)['reg:sp'][0]
        location=engine.location(stack_root,(-32)%(1<<32),32,Endian.LITTLE,'o0')
        self.assertIsNone(old.local_address(near_store))
        self.assertIsNotNone(demand.exact_stack_address(near_store))
        values,killed=demand.memory_definitions(function.entry,len(effects),location,
            ArgumentRead(32,Endian.LITTLE,'o0'),set(),0)
        self.assertTrue(killed)
        self.assertEqual({demand.port.concrete(value) for value in values},{77})
        budgeted=ProcedureDemand(function,old.port,cfg,old.initial)
        budgeted.frontiers.max_must_projection_effects=0
        possible,killed=budgeted.memory_definitions(function.entry,len(effects),location,
            ArgumentRead(32,Endian.LITTLE,'o0'),set(),0)
        self.assertFalse(killed)
        self.assertTrue(possible)
        self.assertTrue(all(budgeted.port.concrete(value) is None for value in possible))

    def test_unknown_sp_clobber_prevents_exact_stack_projection(self):
        sp=ValueRef('clobbered-sp',ptr)
        offset=ValueRef('clobbered-offset',t)
        address=ValueRef('clobbered-address',ptr)
        effects=(UnknownEffect('o0','unsupported-sp','SP may change',(),('sp',),False),
            get('sp',sp),
            Compute('o0',offset,ValueOp.COPY,(Constant(32,t),)),
            Compute('o0',address,ValueOp.SUB,(sp,offset)),
            StoreEffect('o0',address,Constant(77,t),32,Endian.LITTLE,truth))
        old,function,cfg=fixtures.DemandTests().make((effects,))
        demand=ProcedureDemand(function,old.port,cfg,old.initial)
        self.assertFalse(demand.stack_proven)
        self.assertIsNone(demand.exact_stack_address(address))

    def test_guarded_frame_register_definition_is_not_an_exact_stack_address(self):
        sp=ValueRef('guarded-base',t);frame=ValueRef('guarded-frame',t)
        condition=ValueRef('condition',truth.type)
        address=ValueRef('guarded-address',ptr)
        effects=(get('sp',sp),Compute('o0',condition,ValueOp.EQ,(Constant(1,t),Constant(2,t))),
            replace(put('r3',sp),guard=condition),
            get('r3',frame),Compute('o0',address,ValueOp.ADD,(Constant(0,ptr),frame)))
        old,function,cfg=fixtures.DemandTests().make((effects,))
        demand=ProcedureDemand(function,old.port,cfg,old.initial)
        self.assertIsNone(demand.exact_stack_address(address))

    def test_joined_frame_register_definitions_keep_stack_address_unknown(self):
        sp=ValueRef('joined-base',t);frame=ValueRef('joined-frame',t)
        address=ValueRef('joined-address',ptr)
        old,function,cfg=fixtures.DemandTests().make((
            (get('sp',sp),),
            (put('r3',sp),),
            (put('r3',Constant(0x7fffac77,t)),),
            (get('r3',frame),Compute('o0',address,ValueOp.ADD,(Constant(0,ptr),frame)))),
            ((0,1),(0,2),(1,3),(2,3)))
        demand=ProcedureDemand(function,old.port,cfg,old.initial)
        self.assertIsNone(demand.exact_stack_address(address))

