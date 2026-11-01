"""Nested legacy table replacement is a Cartesian product, not diagonal."""
from types import SimpleNamespace
import unittest
from test_p3_contracts import fixture
from emtaint.core import Endian
from emtaint.core.contracts import ValueType,SemanticBudgets
from emtaint.memory import SymbolicOp,AliasKind
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.controlflow.legacy_tables import LegacyTableCollector
from emtaint.compat.legacy_icall_policy import legacy_maximum_address,RV130_SHA256


class TableTests(unittest.TestCase):
    def nested(self):
        _,fid,bid,o,scope,arch,*_=fixture();data=bytearray(0x100)
        for address,value in {0x1000:0x1040,0x1004:0x1080,0x1040:0x2000,0x1044:0x2004,
                              0x1048:0x3000,0x1080:0x2008,0x1084:0x200c,0x1088:0x3000}.items():
            data[address-0x1000:address-0x1000+4]=value.to_bytes(4,'little')
        e=ImageMemoryEngine(scope,arch,(o,),((0x1000,bytes(data),len(data),6),),SemanticBudgets(),initial_policy='legacy-loader-snapshot')
        p=MemoryRuntimePort(e);t=ValueType.bv(32);ptr=ValueType.pointer(32)
        i=p.symbol('i',t,'o0');stride=p.operation(SymbolicOp.MUL,t,(i,p.constant(4,t,'o0')),'o0')
        loads={};truth=p.constant(True,ValueType.boolean(),'o0')
        def deferred(address):
            loc=p.addressed_location(e.location(None,None,32,Endian.LITTLE,'o0'),address)
            ref=p.read(e.initial,loc,truth,'o0').value
            loads[ref]=(address,32,Endian.LITTLE,'o0');return ref
        inner_address=p.operation(SymbolicOp.ADD,ptr,(p.constant(0x1000,ptr,'o0'),stride),'o0')
        inner=deferred(inner_address)
        pointer=p.operation(SymbolicOp.ADD,ptr,(p.constant(0,ptr,'o0'),inner),'o0')
        outer_address=p.operation(SymbolicOp.ADD,ptr,(pointer,stride),'o0');outer=deferred(outer_address)
        demand=SimpleNamespace(port=p,loads=loads,initial=SimpleNamespace(memory=e.initial))
        return demand,inner,outer

    def test_same_origin_unknown_reads_keep_distinct_dependencies_and_may_alias(self):
        d,inner,outer=self.nested();p=d.port;e=p.engine
        self.assertNotEqual(inner,outer)
        a,b=(e.locations[e.dag.nodes[r].location] for r in (inner,outer))
        self.assertNotEqual(p.alias(e.initial,a,b).kind,AliasKind.NO)

    def test_nested_inner_data_then_outer_function_indices(self):
        d,inner,outer=self.nested()
        collector=LegacyTableCollector(d,lambda x:0x2000<=x<0x2100,lambda x:0x1000<=x<0x1100)
        self.assertEqual(collector.collect(outer),(0x2000,0x2004,0x2008,0x200c))
        self.assertTrue(any(x['read_type']=='data' for x in collector.evidence))
        self.assertTrue(any(x['nested_substitutions'] for x in collector.evidence))

    def test_bound_applies_through_pointer_cast_wrappers(self):
        d,inner,outer=self.nested();p=d.port
        wrapped=p.operation(SymbolicOp.ADD,ValueType.pointer(32),(p.constant(0,ValueType.pointer(32),'o0'),outer),'o0')
        collector=LegacyTableCollector(d,lambda x:0x2000<=x<0x2100,lambda x:0x1000<=x<0x1100)
        self.assertEqual(collector.collect(wrapped,maximum_address=0x1040),(0x2000,))

    def test_legacy_site_bound_is_explicit_and_firmware_scoped(self):
        self.assertEqual(legacy_maximum_address(RV130_SHA256,0x2120c),0xa590c)
        self.assertIsNone(legacy_maximum_address('0'*64,0x2120c))
        self.assertIsNone(legacy_maximum_address(RV130_SHA256,0x21404))


if __name__=='__main__':unittest.main()
