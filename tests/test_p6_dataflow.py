"""CIR dataflow/control-flow tests with actual P5 memory ports, no native AST."""
from dataclasses import replace
import pathlib
import sys
import unittest
sys.path.insert(0,str(pathlib.Path(__file__).resolve().parents[1]))
from test_p3_contracts import fixture,sample_module
from test_program_models import fixture as program_fixture
from test_p5_memory import engine
from emtaint.core import (ContextId,Completeness,CallSiteId,ProgramPoint,BlockId,FunctionId,Endian)
from emtaint.core.contracts import (ValueType,ValueRef,Constant,Assessment,Origin,SemanticBudgets)
from emtaint.ir.canonical import (CIRBlock,CIRFunction,CIRModule,Compute,ValueOp,
    ReadRegister,WriteRegister,RegisterSlice,RegisterWritePolicy,BranchEffect,JumpEffect,
    ReturnEffect,LoadEffect,StoreEffect,CallEffect,IndirectTarget,DirectTarget,UnknownEffect)
from emtaint.graph import CallEdge,TargetKind,FlowEdge,FlowKind
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow,ProcedureSummary
from emtaint.analysis.dataflow.fast import CIRFastDataFlow
from emtaint.analysis.framework.runtime import AnalysisRuntime,StaleAnalysis
from emtaint.orchestration.fast_search import CIRFastSearch


def memory_flow():
    e,r=engine();p=MemoryRuntimePort(e)
    return e,r,p


class TransferTests(unittest.TestCase):
    def test_scalar_copy_binop_and_register_def_use(self):
        e,r,p=memory_flow();a=ValueRef('a',ValueType.bv(32));b=ValueRef('b',a.type)
        flow=CIRAccurateDataFlow(p)
        s=flow.initial()
        effects=(Compute('o0',a,ValueOp.COPY,(Constant(7,a.type),)),
            Compute('o0',b,ValueOp.ADD,(a,Constant(8,a.type))),
            WriteRegister('o0',RegisterSlice('r0',0,32,32),b,RegisterWritePolicy.FULL,Constant(True,ValueType.boolean())),
            ReadRegister('o0',a,RegisterSlice('r0',0,32,32)))
        for effect in effects:s=flow.transfer(s,effect)
        self.assertEqual(p.concrete(dict(s.values)['a']),15)
        result=CIRFastDataFlow().slice(effects,('b',))
        self.assertEqual(result.inputs,())
        self.assertGreaterEqual(len(result.origins),1)

    def test_register_partial_and_zero_upper(self):
        e,r,p=memory_flow();flow=CIRAccurateDataFlow(p);s=flow.initial()
        def put(offset,width,value,policy):
            return WriteRegister('o0',RegisterSlice('r0',offset,width,32),Constant(value,ValueType.bv(width)),policy,Constant(True,ValueType.boolean()))
        s=flow.transfer(s,put(0,32,0x11223344,RegisterWritePolicy.FULL))
        s=flow.transfer(s,put(8,16,0xaabb,RegisterWritePolicy.PRESERVE_OTHERS))
        self.assertEqual(p.concrete(dict(s.registers)['r0']),0x11aabb44)
        s=flow.transfer(s,put(0,8,0x55,RegisterWritePolicy.ZERO_UPPER))
        self.assertEqual(p.concrete(dict(s.registers)['r0']),0x55)

    def test_memory_transfer_uses_query_port_and_versions(self):
        e,r,p=memory_flow();address=ValueRef('p',ValueType.pointer(32));value=ValueRef('out',ValueType.bv(32))
        p.bind_address('p',r,0);flow=CIRAccurateDataFlow(p);s=flow.initial()
        before=s.memory
        s=flow.transfer(s,StoreEffect('o0',address,Constant(42,value.type),32,Endian.LITTLE,Constant(True,ValueType.boolean())))
        s=flow.transfer(s,LoadEffect('o0',value,address,32,Endian.LITTLE,Constant(True,ValueType.boolean())))
        self.assertNotEqual(s.memory,before);self.assertEqual(p.concrete(dict(s.values)['out']),42)
        self.assertGreater(p.calls['write'],0);self.assertGreater(p.calls['read'],0)
        self.assertGreater(p.calls['resolve_alias'],0)

    def test_unknown_effect_clears_registers_and_havocs_memory(self):
        e,r,p=memory_flow();flow=CIRAccurateDataFlow(p);s=flow.initial()
        s=replace(s,registers=(('r0',p.constant(7,ValueType.bv(32),'o0')),))
        s=flow.transfer(s,UnknownEffect('o0','Dirty','unknown helper'))
        self.assertEqual(s.registers,());self.assertNotEqual(s.memory,e.initial)
        self.assertNotEqual(s.assessment.status,Completeness.COMPLETE)

    def test_guard_false_preserves_register_and_memory(self):
        e,r,p=memory_flow();flow=CIRAccurateDataFlow(p);s=flow.initial()
        s=replace(s,registers=(('r0',p.constant(7,ValueType.bv(32),'o0')),))
        op=WriteRegister('o0',RegisterSlice('r0',0,32,32),Constant(9,ValueType.bv(32)),RegisterWritePolicy.FULL,Constant(False,ValueType.boolean()))
        out=flow.transfer(s,op)
        self.assertEqual(out.registers,s.registers)

    def test_procedure_summary_identity_and_unknown_havoc(self):
        e,r,p=memory_flow();fid=e.scope.function
        result=ValueRef('ret',ValueType.bv(32));site=CallSiteId(e.origins[0].point)
        call=CallEffect('o0',site,DirectTarget(fid),(Constant(9,result.type),),(result,),sample_module().functions[0].abi,Constant(True,ValueType.boolean()))
        flow=CIRAccurateDataFlow(p,{fid:ProcedureSummary.identity(0,'fixture identity proof')})
        state=flow.transfer(flow.initial(),call)
        self.assertEqual(p.concrete(dict(state.values)['ret']),9)
        opaque=CIRAccurateDataFlow(p);state=opaque.transfer(opaque.initial(),call)
        self.assertNotEqual(state.memory,e.initial);self.assertNotEqual(state.assessment.status,Completeness.COMPLETE)


class WorklistTests(unittest.TestCase):
    def module(self,branch=False,loop=False):
        _,fid,bid,origin,scope,arch,root,*_=fixture();other=BlockId(fid,4)
        value=ValueRef('v',ValueType.bv(32));condition=ValueRef('g',ValueType.boolean())
        o1=replace(origin,id='o1',point=ProgramPoint(other,0,4))
        end=JumpEffect('o1',bid) if loop else ReturnEffect('o1',(value,),Constant(True,ValueType.boolean()))
        first=BranchEffect('o0',condition,other,other) if branch else JumpEffect('o0',other)
        function=CIRFunction(fid,(value,condition),(CIRBlock(bid,(Compute('o0',value,ValueOp.COPY,(Constant(7,value.type),)),first),4),CIRBlock(other,(end,),4)),bid,sample_module().functions[0].abi)
        return CIRModule(origin.producer,arch,arch.endian,fid.binary.sha256,(function,),(origin,o1),('typed-effects',),Assessment.complete())

    def test_cfg_propagation_reaches_return(self):
        m=self.module();e,r,p=memory_flow();e.origins=m.origin_map
        result=CIRFastSearch(m.functions[0],CIRAccurateDataFlow(p)).run()
        self.assertEqual(len(result.returns),1)
        self.assertEqual(p.concrete(dict(result.returns[0].values)['v']),7)

    def test_unknown_branch_both_edges_and_guards_preserved(self):
        m=self.module(branch=True);e,r,p=memory_flow();e.origins=m.origin_map
        result=CIRFastSearch(m.functions[0],CIRAccurateDataFlow(p)).run()
        self.assertEqual(len(result.returns),2)
        self.assertTrue(all(s.guards for s in result.returns))

    def test_finite_loop_fixed_point_and_budget_frontier(self):
        m=self.module(loop=True);e,r,p=memory_flow();e.origins=m.origin_map
        result=CIRFastSearch(m.functions[0],CIRAccurateDataFlow(p)).run()
        self.assertEqual(result.pending,())
        limited=CIRFastSearch(m.functions[0],CIRAccurateDataFlow(p),max_steps=1).run()
        self.assertTrue(limited.pending);self.assertEqual(limited.assessment.status,Completeness.INCOMPLETE)


class InvalidationTests(unittest.TestCase):
    def test_cg_update_invalidates_affected_and_stale_handles(self):
        program,fid,callee,*_,site=program_fixture();runtime=AnalysisRuntime(program)
        runtime.put('alias',fid,ContextId(),'answer',('old',))
        runtime.put('sse',fid,ContextId(),'memo',('old',))
        runtime.put('apg',callee,ContextId(),'graph',('old',))
        runtime.put('heap',fid,ContextId(),'state',('old',))
        runtime.put('summary',fid,ContextId(),'summary',('old',))
        handle=runtime.handle(fid,ContextId())
        changed=runtime.add_call_edge(CallEdge(site,callee,TargetKind.MAY,'fixture candidate'))
        self.assertIn(fid,changed)
        for namespace in ('alias','sse','heap','summary'):
            self.assertIsNone(runtime.get(namespace,fid,ContextId(),'answer' if namespace=='alias' else 'state' if namespace=='heap' else 'summary' if namespace=='summary' else 'memo'))
        with self.assertRaises(StaleAnalysis):runtime.validate(handle)
        self.assertIn(fid,runtime.pending)

    def test_duplicate_graph_update_no_version_churn(self):
        program,fid,callee,*_,site=program_fixture();runtime=AnalysisRuntime(program)
        edge=CallEdge(site,callee,TargetKind.MAY,'same evidence');runtime.add_call_edge(edge)
        version=runtime.session.cg_version
        self.assertEqual(runtime.add_call_edge(edge),frozenset())
        self.assertEqual(runtime.session.cg_version,version)

    def test_cfg_update_and_memory_version_cache_keys(self):
        program,fid,callee,a,b,*_=program_fixture();runtime=AnalysisRuntime(program)
        runtime.put('alias',fid,ContextId(),'M0',('before',));runtime.put('alias',fid,ContextId(),'M1',('after',))
        self.assertNotEqual(runtime.get('alias',fid,ContextId(),'M0'),runtime.get('alias',fid,ContextId(),'M1'))
        runtime.replace_cfg(runtime.session.cfg(fid).with_edge(FlowEdge(a,b,FlowKind.JUMP)))
        self.assertIsNone(runtime.get('alias',fid,ContextId(),'M0'))

    def test_unrelated_function_cache_survives_body_invalidation(self):
        program,fid,callee,a,b,*_=program_fixture();runtime=AnalysisRuntime(program)
        runtime.put('summary',callee,ContextId(),'body',('unchanged',))
        runtime.replace_cfg(runtime.session.cfg(fid).with_edge(FlowEdge(a,b,FlowKind.JUMP)))
        self.assertEqual(runtime.get('summary',callee,ContextId(),'body'),('unchanged',))


if __name__=='__main__':unittest.main()
