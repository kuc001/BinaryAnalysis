"""Region taint respects order/coverage/guards and never turns havoc clean."""
import unittest
from test_p5_memory import engine
from emtaint.core import Endian,MemoryObject,MemoryObjectId
from emtaint.core.contracts import ValueType
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.taint.regions import RegionTaintTracker
from emtaint.memory import AccessRoot,ObjectCardinality,ObjectLifetime


class RegionTests(unittest.TestCase):
    def setup_region(self):
        e,root=engine();p=MemoryRuntimePort(e);tracker=RegionTaintTracker(p)
        location=e.location(root,0,32,Endian.LITTLE,'o0');true=p.constant(True,ValueType.boolean(),'o0')
        source=p.symbol('network',ValueType.bv(32),'o0');state=p.write(e.initial,location,source,true,'o0').state
        tracker.bind(state,location,'recv-site','o0',constraints=(1024,),provenance=('recv buffer',))
        return e,p,tracker,root,location,state,true

    def test_source_has_stable_root_apg_context_version_and_real_alias_queries(self):
        e,p,t,r,loc,m,g=self.setup_region();flows=t.query(m,loc,'o0')
        self.assertEqual(len(flows),1);self.assertFalse(flows[0].confirmed)
        self.assertEqual(flows[0].binding.fact.root,r)
        self.assertEqual(flows[0].binding.fact.memory_version,m)
        self.assertIn(flows[0].binding.fact.graph,e.graphs)
        self.assertGreater(p.calls['resolve_alias'],0)

    def test_exact_clean_overwrite_kills_new_read_but_retains_old_version(self):
        e,p,t,r,loc,m,g=self.setup_region()
        clean=p.write(m,loc,p.constant(0,ValueType.bv(32),'o0'),g,'o0').state
        self.assertEqual(t.query(clean,loc,'o0'),());self.assertTrue(t.query(m,loc,'o0'))

    def test_partial_overwrite_kills_only_covered_bytes(self):
        e,p,t,r,loc,m,g=self.setup_region();middle=e.location(r,1,16,Endian.LITTLE,'o0')
        clean=p.write(m,middle,p.constant(0,ValueType.bv(16),'o0'),g,'o0').state
        self.assertEqual(t.query(clean,e.location(r,1,8,Endian.LITTLE,'o0'),'o0'),())
        self.assertTrue(t.query(clean,e.location(r,0,8,Endian.LITTLE,'o0'),'o0'))
        self.assertTrue(t.query(clean,loc,'o0'))

    def test_unknown_guard_and_havoc_preserve_possible_previous_source(self):
        e,p,t,r,loc,m,g=self.setup_region();guard=p.symbol('condition',ValueType.boolean(),'o0')
        conditional=p.write(m,loc,p.constant(0,ValueType.bv(32),'o0'),guard,'o0').state
        self.assertTrue(t.query(conditional,loc,'o0'))
        unknown=p.havoc(m,('*',),'opaque external write','o0')
        flows=t.query(unknown,loc,'o0');self.assertTrue(flows);self.assertTrue(all(f.incomplete for f in flows))
        false=p.constant(False,ValueType.boolean(),'o0');self.assertEqual(t.query(m,loc,'o0',(false,)),())

    def test_join_preserves_taint_and_bounded_region_uses_unknown_offset_path(self):
        from emtaint.memory import JoinInput
        e,p,t,r,loc,m,g=self.setup_region()
        joined=e.join((JoinInput(m,g),JoinInput(e.initial,g)),'o0')
        self.assertTrue(t.query(joined,loc,'o0'))
        wide=e.location(r,0,8,Endian.LITTLE,'o0',upper=100)
        t.bind(joined,wide,'ranged-source','o0')
        self.assertTrue(t.query(joined,e.location(r,50,8,Endian.LITTLE,'o0'),'o0'))

    def test_global_and_heap_sources_keep_distinct_roots_versions_and_kills(self):
        e,_=engine();p=MemoryRuntimePort(e);tracker=RegionTaintTracker(p)
        global_id=MemoryObjectId.global_object(e.scope.function.binary,'data',0x1000)
        heap_id=MemoryObjectId.heap(e.origins[0].point,e.scope.context,'test-allocation')
        global_root=AccessRoot(global_id,'global','default','o0')
        heap_root=AccessRoot(heap_id,'heap','default','o0')
        e.add_object(MemoryObject(global_id,'test global',64),global_root,
            ObjectCardinality.SINGLETON,ObjectLifetime.STATIC,('fixture global',))
        e.add_object(MemoryObject(heap_id,'test heap',64),heap_root,
            ObjectCardinality.SINGLETON,ObjectLifetime.ALLOCATED,('fixture heap',))
        e.prove_disjoint(global_id,heap_id,'separate fixture storage')
        global_loc=e.location(global_root,0,32,Endian.LITTLE,'o0')
        heap_loc=e.location(heap_root,0,32,Endian.LITTLE,'o0')
        true=p.constant(True,ValueType.boolean(),'o0')
        global_state=p.write(e.initial,global_loc,p.symbol('global-source',ValueType.bv(32),'o0'),true,'o0').state
        global_binding=tracker.bind(global_state,global_loc,'global-source','o0')
        heap_state=p.write(global_state,heap_loc,p.symbol('heap-source',ValueType.bv(32),'o0'),true,'o0').state
        heap_binding=tracker.bind(heap_state,heap_loc,'heap-source','o0')
        self.assertEqual({flow.binding.fact.id for flow in tracker.query(heap_state,global_loc,'o0')},
            {global_binding.fact.id})
        self.assertEqual({flow.binding.fact.id for flow in tracker.query(heap_state,heap_loc,'o0')},
            {heap_binding.fact.id})
        self.assertNotEqual(global_binding.fact.graph,heap_binding.fact.graph)
        self.assertEqual(global_binding.fact.memory_version,global_state)
        self.assertEqual(heap_binding.fact.memory_version,heap_state)
        cleaned=p.write(heap_state,global_loc,p.constant(0,ValueType.bv(32),'o0'),true,'o0').state
        self.assertEqual(tracker.query(cleaned,global_loc,'o0'),())
        self.assertTrue(tracker.query(cleaned,heap_loc,'o0'))

    def test_same_projection_with_distinct_provenance_has_distinct_fact_id(self):
        e,p,tracker,root,location,state,guard=self.setup_region()
        first=tracker.bind(state,location,'recv-site','o0',guard=guard,
            provenance=('caller-path-a',))
        second=tracker.bind(state,location,'recv-site','o0',guard=guard,
            provenance=('caller-path-b',))
        self.assertNotEqual(first.fact.id,second.fact.id)
        self.assertEqual(first.fact.graph,second.fact.graph)
        self.assertEqual({first.fact.id,second.fact.id} & {fact.id for fact in e.facts},
            {first.fact.id,second.fact.id})


if __name__=='__main__':unittest.main()
