import unittest
from dataclasses import replace
from test_p3_contracts import fixture
from emtaint.core import ABI,Register
from emtaint.core.contracts import Assessment,Constant,ValueType
from emtaint.ir.canonical import CIRBlock,CIRFunction,CIRModule,JumpEffect,CallEffect,ReturnEffect
from emtaint.ir.canonical.wire import dumps,loads
from emtaint.graph import ControlFlowGraph
from emtaint.frontends.tail_calls import complete_tail_calls


class TailCallTests(unittest.TestCase):
    def sample(self):
        binary,fid,bid,origin,scope,arch,*_=fixture()
        arch=replace(arch,registers=(Register('r0',32),))
        abi=ABI('fixture',('r0',),('r0',),caller_saved=('r0',))
        jump=JumpEffect(origin.id,Constant(0x1000,ValueType.pointer(32)))
        function=CIRFunction(fid,(),(CIRBlock(bid,(jump,)),),bid,abi)
        module=CIRModule(origin.producer,arch,arch.endian,binary.sha256,(function,),(origin,),('typed-effects',),Assessment.complete())
        cfg=ControlFlowGraph(fid,frozenset((bid,)),entry=bid)
        return module,cfg

    def test_native_target_and_actual_plt_are_both_required(self):
        module,cfg=self.sample();hints=({'instruction':0,'target':'recv'},)
        for plt in ({},{'recv':0x2000}):
            result,graph,rows=complete_tail_calls(module,cfg,hints,0,plt)
            self.assertIs(result,module);self.assertFalse(rows)
        result,graph,rows=complete_tail_calls(module,cfg,hints,0,{'recv':0x1000})
        effects=result.functions[0].blocks[0].effects
        self.assertTrue(any(isinstance(effect,CallEffect) for effect in effects))
        self.assertIsInstance(effects[-1],ReturnEffect)
        self.assertIn(result.functions[0].entry,graph.exits)
        self.assertEqual(rows[0]['native_origin'],'o0')
        self.assertEqual(loads(dumps(result)),result)
        self.assertIsInstance(module.functions[0].blocks[0].effects[-1],JumpEffect)

    def test_missing_call_metadata_does_not_promote_native_jump(self):
        module,cfg=self.sample()
        result,graph,rows=complete_tail_calls(module,cfg,(),0,{'recv':0x1000})
        self.assertIs(result,module);self.assertEqual(rows,())
