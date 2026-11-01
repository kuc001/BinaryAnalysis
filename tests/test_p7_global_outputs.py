"""Old argument/global definition export through actual caller memory queries."""
import unittest
from dataclasses import replace
import test_p7_demand as fixtures
from emtaint.core.contracts import Constant,ValueType
from emtaint.ir.canonical import CIRBlock,DirectTarget,ReturnEffect,StoreEffect
from emtaint.analysis.taint.demand import LegacyTaintDemand,TaintDependency,TaintProcedureSummary
from emtaint.analysis.taint.global_outputs import location as global_location
from emtaint.analysis.taint.global_outputs import GlobalTaintOutput
from emtaint.analysis.taint.global_outputs import candidates as global_candidates
from emtaint.memory import AliasKind
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.analysis.taint.summary_join import SummaryAccumulator


class GlobalOutputTests(unittest.TestCase):
    def callee(self):
        owner,bid=fixtures.TaintDemandTests().make((('recv',(0,0x2000,16,0),True),('placeholder',(),True)))
        effects=owner.function.blocks[0].effects
        function=replace(owner.function,blocks=(CIRBlock(bid,(effects[0],ReturnEffect('o1',(),Constant(True,ValueType.boolean())))),))
        demand=LegacyTaintDemand(function,owner.port,owner.cfg,owner.demand.initial)
        summary=demand.analyze()
        return summary,demand

    def caller(self,summary):
        owner,bid=fixtures.TaintDemandTests().make((('inner',(),True),('strcpy',(0x1000,0x2004),True)))
        effects=list(owner.function.blocks[0].effects)
        fid=replace(bid.function,rva=0x400);effects[0]=replace(effects[0],target=DirectTarget(fid))
        function=replace(owner.function,blocks=(CIRBlock(bid,tuple(effects)),))
        return LegacyTaintDemand(function,owner.port,owner.cfg,owner.demand.initial,summaries={0x400:replace(summary,function=0x400)}),bid

    def test_actual_global_source_is_exported_with_its_write_extent(self):
        summary,demand=self.callee()
        outputs=[value for value in summary.global_outputs if value.address==0x2000]
        self.assertTrue(outputs)
        self.assertEqual(outputs[0].span,16);self.assertEqual(outputs[0].width_bits,8)
        self.assertTrue(any(dep.kind=='source' and dep.value==0 for dep in outputs[0].dependencies))
        self.assertTrue(demand.port.engine.facts)

    def test_caller_reads_actual_callee_global_write_and_keeps_order_and_extent(self):
        summary,_=self.callee();demand,bid=self.caller(summary)
        pointer=demand.port.constant(0x2004,ValueType.bv(32),'o1')
        self.assertFalse(any(dep.kind=='source' for dep in demand.buffer(bid,0,pointer,'o1')))
        self.assertTrue(any(dep.kind=='source' for dep in demand.buffer(bid,1,pointer,'o1')))
        outside=demand.port.constant(0x2018,ValueType.bv(32),'o1')
        # P5 leaves an offset-range location as MayAlias even outside its
        # recorded range. P7 must retain that conservative, uncertain result.
        output=summary.global_outputs[0]
        self.assertEqual(demand.port.alias(demand.demand.initial.memory,global_location(demand,output,'o0'),demand.location(outside,'o1')).kind,AliasKind.MAY)
        self.assertTrue(all(dep.uncertain for dep in demand.buffer(bid,1,outside,'o1') if dep.kind=='source'))
        self.assertTrue(demand.port.engine.facts)

    def test_clean_local_definition_after_global_callee_kills_only_covered_bytes(self):
        summary,_=self.callee()
        owner,bid=fixtures.TaintDemandTests().make((('inner',(),True),'clean'))
        effects=list(owner.function.blocks[0].effects)
        effects[0]=replace(effects[0],target=DirectTarget(replace(bid.function,rva=0x400)))
        function=replace(owner.function,blocks=(CIRBlock(bid,tuple(effects)),))
        demand=LegacyTaintDemand(function,owner.port,owner.cfg,owner.demand.initial,summaries={0x400:replace(summary,function=0x400)})
        first=demand.port.constant(0x2000,ValueType.bv(32),'o1');other=demand.port.constant(0x2004,ValueType.bv(32),'o1')
        self.assertFalse(any(dep.kind=='source' for dep in demand.buffer(bid,2,first,'o1',byte_access=True)))
        self.assertTrue(any(dep.kind=='source' for dep in demand.buffer(bid,2,other,'o1',byte_access=True)))

    def test_exact_scalar_store_export_uses_width_and_does_not_taint_disjoint_bytes(self):
        owner,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),'clean',('placeholder',(),True)))
        effects=list(owner.function.blocks[0].effects)
        # A scalar load from a source-backed buffer is already characterized
        # by the P7 value/byte rules; use a real LoadEffect as Store's input.
        from emtaint.core.contracts import ValueRef
        from emtaint.ir.canonical import LoadEffect
        value=ValueRef('copied-word',ValueType.bv(32));truth=Constant(True,ValueType.boolean())
        effects[1]=LoadEffect('o1',value,Constant(0x1000,ValueType.pointer(32)),32,owner.port.engine.architecture.endian,truth)
        store=StoreEffect('o2',Constant(0x2000,ValueType.pointer(32)),value,32,owner.port.engine.architecture.endian,truth)
        # The new return has an actual registered origin.
        origin=owner.port.engine.origins[-1]
        owner.port.engine.origins+=(replace(origin,id='o3',point=replace(origin.point,statement=3)),)
        effects[2:]=[store,ReturnEffect('o3',(),truth)]
        function=replace(owner.function,values=(value,),blocks=(CIRBlock(bid,tuple(effects)),))
        callee=LegacyTaintDemand(function,owner.port,owner.cfg,owner.demand.initial).analyze()
        output=next(value for value in callee.global_outputs if value.address==0x2000)
        self.assertEqual((output.width_bits,output.span),(32,1))
        caller,bid=self.caller(callee)
        pointer=caller.port.constant(0x2018,ValueType.bv(32),'o1')
        self.assertEqual(caller.port.alias(caller.demand.initial.memory,global_location(caller,output,'o0'),caller.location(pointer,'o1')).kind,AliasKind.NO)
        self.assertFalse(any(dep.kind=='source' for dep in caller.buffer(bid,1,pointer,'o1')))

    def test_interrupted_export_preserves_known_source_and_unknown_frontier(self):
        _,demand=self.callee();output=next(iter(demand.completed_global_outputs.values()))
        demand.active_global_output=output;demand.query_sources={TaintDependency('source',0x900)}
        summary=demand.partial_summary(DemandLimit('injected global export budget'))
        self.assertTrue(any(dep.kind=='source' and dep.value==0x900 for out in summary.global_outputs for dep in out.dependencies))
        self.assertTrue(any(dep.kind=='unknown' for out in summary.global_outputs for dep in out.dependencies))

    def test_same_body_join_keeps_global_source_but_actual_body_change_clears_it(self):
        source=TaintDependency('source',0x900)
        output=GlobalTaintOutput(0x2000,8,self.callee()[1].port.engine.architecture.endian,1,'o0',(source,))
        initial=TaintProcedureSummary(0x400,global_outputs=(output,))
        state=SummaryAccumulator();state.update('body-a',initial)
        partial=TaintProcedureSummary(0x400,pending=('budget',),global_outputs=())
        self.assertEqual(state.update('body-a',partial).global_outputs,(output,))
        self.assertEqual(state.update('body-b',partial).global_outputs,())

    def test_incomplete_callee_cannot_turn_into_a_clean_global_effect_in_its_caller(self):
        summary,_=self.callee();summary=replace(summary,global_outputs=(),outputs=(),pending=('interrupted before globals',))
        demand,bid=self.caller(summary);call=demand.function.blocks[0].effects[0]
        self.assertEqual(global_candidates(demand,bid,0,call),())
        self.assertTrue(any('additional global definitions' in reason for origin,reason in demand.pending))

    def test_old_same_location_merge_keeps_all_new_source_evidence_with_a_representative_origin(self):
        summary,_=self.callee();output=summary.global_outputs[0]
        other=replace(output,origin='another-real-write',dependencies=(TaintDependency('source',0xa00),))
        state=SummaryAccumulator();state.update('body',replace(summary,global_outputs=(output,)))
        result=state.update('body',replace(summary,global_outputs=(other,)))
        self.assertEqual(len(result.global_outputs),1)
        self.assertEqual({value.value for value in result.global_outputs[0].dependencies if value.kind=='source'},{0,0xa00})
        self.assertEqual(result.global_outputs[0].origin,output.origin)

    def test_a_modeled_plt_procedure_does_not_require_an_unrelated_internal_summary(self):
        _,owner=self.callee();block=owner.function.blocks[0];effects=list(block.effects)
        effects[0]=replace(effects[0],target=DirectTarget(replace(block.id.function,rva=0x400)))
        function=replace(owner.function,blocks=(CIRBlock(block.id,tuple(effects)),))
        d=LegacyTaintDemand(function,owner.port,owner.cfg,owner.demand.initial,names={0:'recv'})
        summary=d.analyze()
        self.assertFalse(summary.pending)
        self.assertTrue(any(dep.kind=='source' for output in summary.global_outputs or () for dep in output.dependencies))
