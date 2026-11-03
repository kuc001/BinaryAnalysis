"""Legacy entry policy and loader snapshot are explicit, versioned inputs."""
import unittest
from test_p3_contracts import fixture
from emtaint.core import Endian
from emtaint.core.contracts import SemanticBudgets,ValueType
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry


class EntryTests(unittest.TestCase):
    def image(self,policy):
        _,fid,bid,origin,scope,arch,*_=fixture()
        return ImageMemoryEngine(scope,arch,(origin,),((0x1000,b'\x78\x56\x34\x12',8,6),),
                                 SemanticBudgets(),initial_policy=policy)

    def test_writable_loader_snapshot_does_not_bypass_writes_or_havoc(self):
        e=self.image('legacy-loader-snapshot');p=MemoryRuntimePort(e)
        root,offset=e.address(0x1000);loc=e.location(root,offset,32,Endian.LITTLE,'o0')
        truth=p.constant(True,ValueType.boolean(),'o0')
        read=lambda state:p.read(state,loc,truth,'o0').value
        self.assertEqual(p.concrete(read(e.initial)),0x12345678)
        m=p.write(e.initial,loc,p.constant(99,ValueType.bv(32),'o0'),truth,'o0').state
        self.assertEqual(p.concrete(read(m)),99)
        m=p.havoc(m,('*',),'unknown external write','o0')
        self.assertIsNone(p.concrete(read(m)))
        self.assertEqual(p.concrete(read(e.initial)),0x12345678)

    def test_default_entry_does_not_assume_writable_pristine(self):
        e=self.image('readonly-at-entry');p=MemoryRuntimePort(e)
        root,offset=e.address(0x1000);loc=e.location(root,offset,32,Endian.LITTLE,'o0')
        self.assertIsNone(p.concrete(p.read(e.initial,loc,p.constant(True,ValueType.boolean(),'o0'),'o0').value))

    def test_stack_sentinel_and_stable_argument_roots(self):
        e=self.image('legacy-loader-snapshot');p=MemoryRuntimePort(e)
        state=legacy_entry(CIRAccurateDataFlow(p))
        self.assertEqual(p.concrete(dict(state.registers)['sp']),0x7fffffff)
        self.assertEqual(len(e.objects),10)
        stack=dict(state.addresses)['reg:sp'][0]
        self.assertEqual(stack.object_id.function,e.scope.function)
        self.assertEqual(stack.object_id.context,e.scope.context)
        a,b=(dict(state.addresses)['reg:'+name][0] for name in ('r0','r1'))
        self.assertFalse(e._disjoint(a.object_id,b.object_id))

    def test_native_abi_can_separate_arguments_from_new_callee_frame(self):
        e=self.image('legacy-loader-snapshot');p=MemoryRuntimePort(e)
        state=legacy_entry(CIRAccurateDataFlow(p), arguments_outside_frame=True)
        stack=dict(state.addresses)['reg:sp'][0]
        a,b=(dict(state.addresses)['reg:'+name][0] for name in ('r0','r1'))
        self.assertTrue(e._disjoint(stack.object_id,a.object_id))
        self.assertTrue(e._disjoint(stack.object_id,b.object_id))
        self.assertFalse(e._disjoint(a.object_id,b.object_id))


if __name__=='__main__':unittest.main()
