"""Backward definitions, loop substitution and versioned memory demand."""
import unittest
from dataclasses import replace
from test_p3_contracts import fixture
from emtaint.core import ABI,BlockId,Endian,FunctionId,ProgramPoint
from emtaint.core.contracts import ValueType,ValueRef,Constant,SemanticBudgets
from emtaint.ir.canonical import (CIRFunction,CIRBlock,Compute,ValueOp,LoadEffect,StoreEffect,
    ReadRegister,WriteRegister,RegisterSlice,RegisterWritePolicy,JumpEffect)
from emtaint.graph import ControlFlowGraph,FlowEdge,FlowKind
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.dataflow.legacy_demand import LegacyDemand
from emtaint.analysis.controlflow.local_constants import local_constant_edges
from emtaint.analysis.controlflow.legacy_tables import LegacyTableCollector

t=ValueType.bv(32);ptr=ValueType.pointer(32);truth=Constant(True,ValueType.boolean())
def put(name,value):return WriteRegister('o0',RegisterSlice(name,0,32,32),value,RegisterWritePolicy.FULL,truth)
def get(name,result):return ReadRegister('o0',result,RegisterSlice(name,0,32,32))


class DemandTests(unittest.TestCase):
    def make(self,block_effects,edges=(),*,function_rva=0,session='fixture-session'):
        _,fid,bid,origin,scope,arch,*_=fixture()
        fid=FunctionId(fid.binary,function_rva);bid=BlockId(fid,function_rva)
        origin=replace(origin,point=ProgramPoint(bid,0,function_rva))
        scope=replace(scope,function=fid,session_id=session)
        blocks=tuple(CIRBlock(BlockId(fid,function_rva+i*4),tuple(e)) for i,e in enumerate(block_effects))
        declared={e.result for b in blocks for e in b.effects if hasattr(e,'result')}
        declared.update(v for b in blocks for e in b.effects for v in getattr(e,'results',()))
        f=CIRFunction(fid,tuple(declared),blocks,bid,ABI('fixture'))
        cfg=ControlFlowGraph(fid,frozenset(b.id for b in blocks),frozenset(FlowEdge(blocks[a].id,blocks[b].id,FlowKind.JUMP) for a,b in edges),bid)
        e=ImageMemoryEngine(scope,arch,(origin,),((0x1000,bytes.fromhex('002000000420000000000000'),12,6),),SemanticBudgets(),initial_policy='legacy-loader-snapshot')
        p=MemoryRuntimePort(e);initial=legacy_entry(CIRAccurateDataFlow(p))
        return LegacyDemand(f,p,cfg,initial),f,cfg

    def test_cross_block_register_definition_and_load(self):
        a=ValueRef('a',t);b=ValueRef('b',t)
        d,_,_=self.make(((put('r4',Constant(0x1000,t)),),(get('r4',a),LoadEffect('o0',b,Constant(0x1000,ptr),32,Endian.LITTLE,truth))),((0,1),))
        self.assertEqual({d.port.concrete(x) for x in d.value(a)},{0x1000})
        self.assertEqual({d.port.concrete(x) for x in d.value(b)},{0x2000})
        self.assertGreater(d.port.calls['read'],0)
        self.assertGreater(len(d.port.engine.graphs),0)

    def test_stack_frame_proof_rejects_global_escape_and_unbounded_sp_loop(self):
        a=ValueRef('sp',t);b=ValueRef('offset',t)
        effects=(get('sp',a),Compute('o0',b,ValueOp.SUB,(a,Constant(0x7fffefff,t))),put('sp',b))
        d,_,_=self.make((effects,))
        self.assertFalse(d.stack_proven)
        self.assertEqual(d.address_binding(d.value(b)[0]),d.port.engine.address(0x1000))
        loop=(get('sp',a),Compute('o0',b,ValueOp.SUB,(a,Constant(4,t))),put('sp',b))
        d,_,_=self.make((loop,),((0,0),))
        self.assertFalse(d.stack_proven)

    def test_balanced_sp_loop_is_finite_and_stack_input_is_killed_by_store(self):
        a=ValueRef('sp',t);b=ValueRef('offset',t);c=ValueRef('restored',t);out=ValueRef('out',t)
        effects=(get('sp',a),Compute('o0',b,ValueOp.SUB,(a,Constant(8,t))),put('sp',b),
                 Compute('o0',c,ValueOp.ADD,(b,Constant(8,t))),put('sp',c))
        d,_,_=self.make((effects,),((0,0),));self.assertTrue(d.stack_proven)
        load=LoadEffect('o0',out,Constant(0x7fffffff,ptr),32,Endian.LITTLE,truth)
        d,_,_=self.make(((load,),));values=d.value(out)
        self.assertEqual({d.port.engine.dag.nodes[x].value for x in values},{'argument:4'})
        store=StoreEffect('o0',Constant(0x7fffffff,ptr),Constant(99,t),32,Endian.LITTLE,truth)
        d,_,_=self.make(((store,load),));self.assertEqual({d.port.concrete(x) for x in d.value(out)},{99})

    def test_full_store_kills_snapshot_and_preserves_memory_version(self):
        b=ValueRef('b',t);address=Constant(0x1000,ptr)
        d,_,_=self.make(((StoreEffect('o0',address,Constant(0x3000,t),32,Endian.LITTLE,truth),LoadEffect('o0',b,address,32,Endian.LITTLE,truth)),))
        self.assertEqual({d.port.concrete(x) for x in d.value(b)},{0x3000})
        self.assertGreater(d.port.calls['resolve_alias'],0)
        self.assertGreater(len(d.port.engine.versions),1)

    def test_loop_increment_is_legacy_base_plus_i_times_stride(self):
        a=ValueRef('a',t);b=ValueRef('b',t);out=ValueRef('out',t)
        d,_,_=self.make(((put('r4',Constant(0x1000,t)),),
            (get('r4',a),Compute('o0',b,ValueOp.ADD,(a,Constant(4,t))),put('r4',b)),
            (get('r4',out),)),((0,1),(1,1),(1,2)))
        collector=LegacyTableCollector(d,lambda x:0x2000<=x<0x3000,lambda x:False)
        # Direct old _summary_variable_in_loop characterization: 0x1000+4*i.
        # i denotes the legacy summary index, not the concrete iteration count.
        self.assertIn(0x100c,{collector.evaluate(ref,3) for ref in d.value(out)})
        self.assertTrue(any('summary_variable' in rule for rule in d.rules))

    def test_local_pc_constants_add_cfg_edge(self):
        a=ValueRef('pcvalue',t);p=ValueRef('pcptr',ptr)
        _,f,cfg=self.make(((put('pc',Constant(4,t)),get('pc',a),
            Compute('o0',p,ValueOp.ADD,(Constant(0,ptr),a)),JumpEffect('o0',p)),()),())
        complete=local_constant_edges(f,cfg,0)
        self.assertTrue(any(edge.source==f.entry and edge.target==f.blocks[1].id for edge in complete.edges))

    def test_table_candidate_queries_versioned_snapshot(self):
        v=ValueRef('v',t)
        d,_,_=self.make(((LoadEffect('o0',v,Constant(0x1000,ptr),32,Endian.LITTLE,truth),),))
        collector=LegacyTableCollector(d,lambda x:0x2000<=x<0x3000,lambda x:False)
        self.assertEqual(collector.collect(d.value(v)[0]),(0x2000,))


if __name__=='__main__':unittest.main()
