import unittest
from test_p5_memory import engine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.core.contracts import ValueType,record_annotations


class RuntimeCacheTests(unittest.TestCase):
    def test_concrete_cache_keeps_memory_versions_and_stale_port_checks(self):
        e,root=engine();p=MemoryRuntimePort(e);loc=e.location(root,0,8,e.architecture.endian,'o0')
        truth=p.constant(True,ValueType.boolean(),'o0')
        a=p.write(e.initial,loc,p.constant(7,ValueType.bv(8),'o0'),truth,'o0').state
        first=p.read(a,loc,truth,'o0').value
        self.assertEqual(p.concrete(first),7)
        b=p.write(a,loc,p.constant(9,ValueType.bv(8),'o0'),truth,'o0').state
        second=p.read(b,loc,truth,'o0').value
        self.assertEqual((p.concrete(first),p.concrete(second)),(7,9))
        def stale():raise RuntimeError('stale scope')
        p.validate_current=stale
        with self.assertRaisesRegex(RuntimeError,'stale scope'):p.concrete(first)

    def test_type_metadata_cache_is_immutable_and_validation_remains_strict(self):
        annotations=record_annotations(ValueType)
        with self.assertRaises(TypeError):annotations['bits']=str
        with self.assertRaises(TypeError):ValueType.bv(True)

    def test_all_passes_share_graph_ids_and_conflicting_replacement_is_rejected(self):
        from dataclasses import replace
        from emtaint.memory import Offset,Deref
        from emtaint.analysis.taint.regions import RegionTaintTracker
        e,root=engine();first=MemoryRuntimePort(e);second=MemoryRuntimePort(e)
        self.assertIs(first.apg,second.apg);self.assertIs(RegionTaintTracker(first).apg,first.apg)
        path=e.path(root,(Offset(0),Deref(32,8,e.architecture.endian)),8,e.architecture.endian,'o0')
        graph=first.apg.intern(path,e.origins[0].point);e.add_graph(graph)
        another=second.apg.intern(replace(path,segments=(Offset(4),Deref(32,8,e.architecture.endian))),e.origins[0].point)
        self.assertNotEqual(graph.id,another.id)
        with self.assertRaisesRegex(ValueError,'Conflicting AccessGraphId'):e.add_graph(replace(graph,accepting=graph.entries))
        self.assertEqual(e.graphs[graph.id],graph)
