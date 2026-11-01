"""Focused memory-dependent may-flow tests; no whole-program finding claims."""
import unittest
from dataclasses import replace
from test_p5_memory import engine
from emtaint.core import Endian,Completeness
from emtaint.core.contracts import Assessment,Precision,ValueType
from emtaint.memory import Offset,Deref,TaintFact,APGNode,APGEdge
from emtaint.memory.access_graph import AccessGraphArena
from emtaint.analysis.taint import MemoryTaintTracker
from emtaint.memory.query_port import QueryBudget
from emtaint.memory.policies import BudgetExceeded
from emtaint.ir.canonical.wire import dumps,loads
from emtaint.memory.engine import PythonMemoryEngine


def tainted():
    e,r=engine();arena=AccessGraphArena(e.scope,e.budgets)
    graph=arena.field_closure(r,((Offset(8),Deref(32,32,Endian.LITTLE)),),e.origins[0].point)
    graph=replace(graph,nodes=graph.nodes+(APGNode('data'),),edges=(APGEdge('n0','data',Offset(0)),),accepting=('data',))
    e.add_graph(graph);g=e.dag.symbol('source-path-guard',ValueType.boolean(),'o0')
    source=e.dag.symbol('source-input',ValueType.bv(32),'o0')
    fact=TaintFact('source',r,None,graph.id,e.scope.context,e.initial,g,'may-source','o0',
        ('Source(arg)','arg.next*.data'),
        Assessment(Completeness.COMPLETE,Precision.OVER_APPROX,('May-flow only',),diagnostics=()))
    tracker=MemoryTaintTracker(e);tracker.mark_source(source,fact)
    return e,r,tracker,source,g


class MemoryTaintTests(unittest.TestCase):
    def test_source_store_load_reaches_sink_with_guard_and_version(self):
        e,r,t,source,g=tainted();loc=e.location(r,0,32,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,source,g,'o0');value=e.load(m,loc)
        candidates=t.sink(value,m,'o0')
        self.assertEqual(len(candidates),1)
        c=candidates[0]
        self.assertEqual(c['source'],'source');self.assertIn(g,c['guards'])
        self.assertEqual(c['memory_version'],m);self.assertFalse(c['confirmed'])

    def test_strong_overwrite_kills_old_source_but_old_version_retains_it(self):
        e,r,t,source,g=tainted();loc=e.location(r,0,32,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,source,origin='o0');old=e.load(m,loc)
        new=e.store(m,loc,e.dag.constant(0,32,'o0'),origin='o0')
        self.assertTrue(t.sink(old,m,'o0'))
        self.assertEqual(t.sink(e.load(new,loc),new,'o0'),())

    def test_false_sink_guard_suppresses_flow_and_havoc_is_unknown(self):
        e,r,t,source,g=tainted();loc=e.location(r,0,32,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,source,origin='o0');value=e.load(m,loc)
        self.assertEqual(t.sink(value,m,'o0',e.dag.boolean(False,'o0')),())
        h=e.havoc(m,('*',),'external may overwrite','o0')
        candidates=t.sink(e.load(h,loc),h,'o0')
        self.assertEqual(candidates[0]['status'],'unknown');self.assertFalse(candidates[0]['confirmed'])

    def test_same_wire_and_explicit_source_binding_replays_flow(self):
        e,r,t,source,g=tainted();loc=e.location(r,0,32,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,source,g,'o0');value=e.load(m,loc)
        before=t.sink(value,m,'o0');restored=PythonMemoryEngine.from_snapshot(loads(dumps(e.snapshot())))
        replay=MemoryTaintTracker(restored)
        replay.mark_source(source,restored.facts[0])
        self.assertEqual(replay.sink(value,m,'o0'),before)

    def test_flow_query_budget_never_returns_empty_success(self):
        e,r,t,source,g=tainted();loc=e.location(r,0,32,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,source,g,'o0')
        with self.assertRaises(BudgetExceeded):
            t.sink(e.load(m,loc),m,'o0',budget=QueryBudget(max_steps=1))
