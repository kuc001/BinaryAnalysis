import unittest
import itertools
from dataclasses import replace
from test_p5_memory import engine
from emtaint.core.contracts import MemoryLocationId
from emtaint.core import Endian
from emtaint.memory.abstract_heap import ObjectCardinality
from emtaint.compat.memory_runtime import MemoryRuntimePort


class AliasCacheTests(unittest.TestCase):
    def test_cached_geometry_matches_uncached_alias_for_overlaps_ranges_and_unknown(self):
        e,root=engine();port=MemoryRuntimePort(e,cache_alias_queries=True)
        locations=[e.location(root,offset,width,Endian.LITTLE,'o0')
            for offset,width in itertools.product((0,1,4,8),(8,16,32))]
        locations.append(e.location(root,None,32,Endian.LITTLE,'o0'))
        locations.append(e.location(None,None,32,Endian.LITTLE,'o0'))
        for left,right in itertools.product(locations,repeat=2):
            with self.subTest(left=left.id.key,right=right.id.key):
                expected=e.resolve_alias(e.initial,left,right)
                self.assertEqual(port.alias(e.initial,left,right),expected)
                self.assertEqual(port.alias(e.initial,left,right),expected)
        self.assertGreater(port.metrics()['alias_cache_hits'],0)

    def test_fact_change_invalidates_cached_must_and_stale_or_foreign_scope_is_rejected(self):
        e,root=engine();port=MemoryRuntimePort(e,cache_alias_queries=True)
        location=e.location(root,0,32,Endian.LITTLE,'o0')
        self.assertEqual(port.alias(e.initial,location,location).kind.value,'must_alias')
        e.object_facts[root.object_id]=replace(e.object_facts[root.object_id],cardinality=ObjectCardinality.SUMMARY)
        self.assertEqual(port.alias(e.initial,location,location).kind,e.resolve_alias(e.initial,location,location).kind)
        self.assertNotEqual(port.alias(e.initial,location,location).kind.value,'must_alias')
        foreign=replace(location,id=MemoryLocationId(replace(e.scope,session_id='foreign'),'foreign'))
        with self.assertRaises(ValueError):port.alias(e.initial,foreign,location)
        def stale():raise RuntimeError('stale scope')
        port.validate_current=stale
        with self.assertRaisesRegex(RuntimeError,'stale scope'):port.alias(e.initial,location,location)
