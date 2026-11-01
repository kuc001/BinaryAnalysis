"""Target provenance, stale memory handles and image-versus-runtime semantics."""
import unittest
from dataclasses import replace
from test_program_models import fixture
from test_p3_contracts import fixture as memory_fixture
from emtaint.core import ContextId,Endian,Completeness,ProgramPoint
from emtaint.core.contracts import (AnalysisScope,Origin,Producer,ValueRef,ValueType,Constant,
    Assessment,SemanticBudgets,MemoryVersionId)
from emtaint.memory.engine import PythonMemoryEngine
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.ir.canonical import (CIRFunction,CIRBlock,Compute,ValueOp,CallEffect,IndirectTarget,
    ReturnEffect,JumpEffect,LoadEffect,StoreEffect,UnknownEffect,RegisterSlice,ReadRegister)
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.fast import CIRFastDataFlow
from emtaint.analysis.framework.runtime import AnalysisRuntime,StaleAnalysis
from emtaint.analysis.controlflow.targets import TargetGraphUpdater
from emtaint.orchestration.fast_search import CIRFastSearch
from emtaint.orchestration.program_search import CIRProgramSearch
from emtaint.graph import CallEdge,TargetKind,FlowEdge,FlowKind


def setup():
    program,fid,callee,a,b,c,site=fixture();runtime=AnalysisRuntime(program)
    origins=(Origin('o0',site.point,Producer('P6-test','1','fixture'),'test'),
             Origin('o1',ProgramPoint(b,0,4),Producer('P6-test','1','fixture'),'test'))
    scope=AnalysisScope.from_session(runtime.session,fid,ContextId())
    e=PythonMemoryEngine(scope,program.architecture,origins);port=MemoryRuntimePort(e)
    runtime.bind_port(port,fid,ContextId())
    return program,runtime,e,port,origins,(fid,callee,a,b,c,site)


class TargetTests(unittest.TestCase):
    def test_clobbered_register_is_not_correlated_with_old_entry_symbol(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup();flow=CIRAccurateDataFlow(p)
        before=ValueRef('before',ValueType.bv(32));after=ValueRef('after',ValueType.bv(32))
        state=flow.transfer(flow.initial(),ReadRegister('o0',before,RegisterSlice('a0',0,32,32)))
        state=flow.transfer(state,UnknownEffect('o0','Clobber','unknown register update',(),('a0',),False))
        state=flow.transfer(state,ReadRegister('o0',after,RegisterSlice('a0',0,32,32)))
        one=e.dag.nodes[dict(state.values)['before']];two=e.dag.nodes[dict(state.values)['after']]
        self.assertNotEqual(one.value,two.value)

    def test_batch_graph_update_reanalyzes_affected_with_fresh_scopes(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup();revisions=[]
        target=ValueRef('target',ValueType.pointer(32));true=Constant(True,ValueType.boolean())
        fun=CIRFunction(fid,(target,), (CIRBlock(a,(Compute('o0',target,ValueOp.COPY,(Constant(0x1010,target.type),)),
            CallEffect('o0',site,IndirectTarget(target),(),(),program.abi,true),JumpEffect('o0',b)),4),
            CIRBlock(b,(ReturnEffect('o1',(),true),),4)),a,program.abi)
        def analyze(function):
            scope=AnalysisScope.from_session(runtime.session,function,ContextId());revisions.append(scope.cg_version)
            port=MemoryRuntimePort(PythonMemoryEngine(scope,program.architecture,origins))
            runtime.bind_port(port,function,ContextId())
            return CIRFastSearch(fun,CIRAccurateDataFlow(port),image_base=0x1000).run()
        result=CIRProgramSearch(runtime,TargetGraphUpdater(runtime,origins),analyze,max_rounds=3).run((fid,))
        self.assertEqual(result.rounds,2);self.assertEqual(revisions,[0,1]);self.assertEqual(result.pending,())

    def test_stale_port_cannot_transfer_pure_compute(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup()
        flow=CIRAccurateDataFlow(p);state=flow.initial()
        runtime.add_call_edge(CallEdge(site,callee,TargetKind.MAY,'new edge'))
        value=ValueRef('v',ValueType.bv(32))
        with self.assertRaises(StaleAnalysis):flow.transfer(state,Compute('o0',value,ValueOp.COPY,(Constant(7,value.type),)))

    def test_partial_register_read_does_not_keep_whole_pointer_binding(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup()
        from emtaint.memory import AccessRoot,ObjectCardinality,ObjectLifetime
        from emtaint.core import MemoryObject,MemoryObjectId
        root=AccessRoot(MemoryObjectId.stack(fid,ContextId(),'frame'),'stack','default','o0')
        e.add_object(MemoryObject(root.object_id,'frame',16),root,ObjectCardinality.SINGLETON,ObjectLifetime.FRAME,('fixture frame',))
        p.bind_address('reg:a0',root,0);flow=CIRAccurateDataFlow(p)
        small=ValueRef('small',ValueType.bv(8));state=flow.transfer(flow.initial(),ReadRegister('o0',small,RegisterSlice('a0',0,8,32)))
        self.assertNotIn('small',dict(state.addresses))

    def test_computed_icall_value_updates_cg_and_keeps_unknown_edge(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup()
        target=ValueRef('target',ValueType.pointer(32));true=Constant(True,ValueType.boolean())
        effects=(Compute('o0',target,ValueOp.COPY,(Constant(0x1010,target.type),)),
            CallEffect('o0',site,IndirectTarget(target),(),(),program.abi,true),JumpEffect('o0',b))
        fun=CIRFunction(fid,(target,),(CIRBlock(a,effects,4),CIRBlock(b,(ReturnEffect('o1',(),true),),4)),a,program.abi)
        result=CIRFastSearch(fun,CIRAccurateDataFlow(p),image_base=program.image_base).run()
        fact=next(x for x in result.targets if x.kind=='icall')
        self.assertEqual(fact.targets,(0x1010,));self.assertEqual(fact.certainty,'confirmed')
        updater=TargetGraphUpdater(runtime,origins);updater.apply((fact,))
        self.assertIn(callee,runtime.session.cg.targets(site));self.assertIn(site,runtime.session.cg.unresolved_sites)
        with self.assertRaises(StaleAnalysis):p.concrete(e.dag.constant(7,8,'o0'))

    def test_unknown_icall_never_reports_exhaustive_empty_set(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup()
        target=ValueRef('unbound',ValueType.pointer(32));true=Constant(True,ValueType.boolean())
        fun=CIRFunction(fid,(target,),(CIRBlock(a,(CallEffect('o0',site,IndirectTarget(target),(),(),program.abi,true),JumpEffect('o0',b)),4),CIRBlock(b,(ReturnEffect('o1',(),true),),4)),a,program.abi)
        result=CIRFastSearch(fun,CIRAccurateDataFlow(p),image_base=0x1000).run()
        fact=result.targets[0]
        self.assertEqual(fact.certainty,'unknown');self.assertFalse(fact.exhaustive)
        self.assertEqual(result.assessment.status,Completeness.INCOMPLETE)

    def test_computed_switch_adds_cfg_edge_with_invalidation(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup()
        target=Constant(0x1004,ValueType.pointer(32));true=Constant(True,ValueType.boolean())
        fun=CIRFunction(fid,(),(CIRBlock(a,(JumpEffect('o0',target),),4),CIRBlock(b,(ReturnEffect('o1',(),true),),4)),a,program.abi)
        result=CIRFastSearch(fun,CIRAccurateDataFlow(p),image_base=0x1000).run()
        TargetGraphUpdater(runtime,origins).apply(result.targets)
        self.assertTrue(any(edge.source==a and edge.target==b and edge.kind==FlowKind.SWITCH for edge in runtime.session.cfg(fid).edges))
        self.assertEqual(runtime.session.cfg_version(fid),1)

    def test_unknown_control_in_loop_stays_incomplete(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup()
        effect=UnknownEffect('o0','UnknownControl','No precise effect',(),(),True)
        fun=CIRFunction(fid,(),(CIRBlock(a,(effect,JumpEffect('o0',a)),4),),a,program.abi)
        result=CIRFastSearch(fun,CIRAccurateDataFlow(p)).run()
        self.assertEqual(result.pending,());self.assertEqual(result.assessment.status,Completeness.INCOMPLETE)

    def test_memory_cache_checks_automatic_version_and_session_scope(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup();handle=runtime.handle(fid,ContextId())
        runtime.memory_put('alias',handle,e.initial,'query',('M0',))
        self.assertEqual(runtime.memory_get('alias',handle,e.initial,'query'),('M0',))
        other=MemoryVersionId(e.scope,'different-state')
        self.assertIsNone(runtime.memory_get('alias',handle,other,'query'))
        runtime.add_call_edge(CallEdge(site,callee,TargetKind.MAY,'test'))
        with self.assertRaises(StaleAnalysis):runtime.memory_get('alias',handle,e.initial,'query')

    def test_transitive_caller_invalidation_uses_reverse_cg(self):
        program,runtime,e,p,origins,(fid,callee,a,b,c,site)=setup()
        runtime.add_call_edge(CallEdge(site,callee,TargetKind.MAY,'dependency'))
        affected=runtime.replace_cfg(runtime.session.cfg(callee).with_edge(FlowEdge(c,c,FlowKind.JUMP)))
        self.assertEqual(affected,frozenset((fid,callee)))


class ImageTests(unittest.TestCase):
    def test_readonly_initial_bytes_and_subsequent_havoc(self):
        _,_,_,origin,scope,arch,*_=memory_fixture()
        e=ImageMemoryEngine(scope,arch,(origin,),((0x1000,b'\x78\x56\x34\x12',4,5),),SemanticBudgets())
        root,offset=e.address(0x1000);loc=e.location(root,offset,32,Endian.LITTLE,'o0')
        read=e.load(e.initial,loc);self.assertEqual(e.constant_value(read),0x12345678)
        later=e.havoc(e.initial,('*',),'unknown call','o0')
        self.assertIsNone(e.constant_value(e.load(later,loc)))
        self.assertEqual(e.constant_value(read),0x12345678)

    def test_writable_image_bytes_not_assumed_pristine_at_function_entry(self):
        _,_,_,origin,scope,arch,*_=memory_fixture()
        e=ImageMemoryEngine(scope,arch,(origin,),((0x1000,b'\x78\x56\x34\x12',4,6),),SemanticBudgets())
        root,offset=e.address(0x1000);loc=e.location(root,offset,32,Endian.LITTLE,'o0')
        self.assertIsNone(e.constant_value(e.load(e.initial,loc)))
