"""Semantic revision, real edge retraction and detached recipe contracts."""
import unittest
from dataclasses import replace
from types import SimpleNamespace
from test_p6_targets import setup
from emtaint.core import ContextId
from emtaint.core.contracts import ValueType
from emtaint.graph import CallEdge,TargetKind
from emtaint.analysis.framework.runtime import StaleAnalysis
from emtaint.analysis.framework.summaries import ProcedureRecipe,SummaryNode
from emtaint.orchestration.legacy_cir_search import run_with_legacy_fallback,callee_first


class RevisionTests(unittest.TestCase):
    def test_changed_recipe_invalidates_caller_caches_and_scoped_ports(self):
        program,r,e,p,origins,(fid,callee,a,b,c,site)=setup();ctx=ContextId()
        r.add_call_edge(CallEdge(site,callee,TargetKind.MAY,'real dependency'))
        # Bind a fresh scoped port after the graph revision.
        from emtaint.core.contracts import AnalysisScope
        from emtaint.memory.engine import PythonMemoryEngine
        from emtaint.compat.memory_runtime import MemoryRuntimePort
        e=PythonMemoryEngine(AnalysisScope.from_session(r.session,fid,ctx),program.architecture,origins)
        p=MemoryRuntimePort(e);r.bind_port(p,fid,ctx);handle=r.handle(fid,ctx)
        recipe=ProcedureRecipe(callee,(SummaryNode(ValueType.bv(32),'constant',value=7),),(0,),(),(),('actual fixture',),())
        r.recipe_put(callee,ctx,recipe)
        for family in ('heap','alias','sse','apg','summary','facts','result'):r.put(family,fid,ctx,'key',('observed',))
        revision=r.session.stamp.state_revision
        self.assertFalse(r.recipe_put(callee,ctx,recipe));self.assertEqual(r.session.stamp.state_revision,revision)
        changed=replace(recipe,nodes=(replace(recipe.nodes[0],value=8),))
        self.assertEqual(r.recipe_put(callee,ctx,changed),frozenset((fid,callee)))
        self.assertIn(fid,r.pending)
        for family in r.NAMESPACES:self.assertIsNone(r.get(family,fid,ctx,'key'))
        with self.assertRaises(StaleAnalysis):p.constant(1,ValueType.bv(32),'o0')
        with self.assertRaises(StaleAnalysis):r.memory_get('heap',handle,e.initial,'key')
        with self.assertRaises(ValueError):r.recipe_put(callee,ctx,replace(changed,provenance=(e.initial,)))

    def test_retraction_preserves_unresolved_and_static_dependencies(self):
        _,r,e,p,o,(fid,callee,a,b,c,site)=setup()
        original=r.session.cg.edges
        inferred=CallEdge(site,callee,TargetKind.MAY,r.INFERRED_PREFIX+'candidate')
        r.replace_inferred_call_edges((site,),(inferred,))
        self.assertIn(callee,r.session.cg.targets(site))
        r.replace_inferred_call_edges((site,),())
        self.assertEqual(r.session.cg.edges,original)
        self.assertIn(site,r.session.cg.unresolved_sites)
        self.assertFalse(r.replace_inferred_call_edges((site,),()))

    def test_dependency_order_and_actual_fallback_callback(self):
        _,r,e,p,o,(fid,callee,a,b,c,site)=setup()
        r.add_call_edge(CallEdge(site,callee,TargetKind.MAY,'dependency'))
        self.assertEqual(callee_first((fid,callee),r.session.cg),(callee,fid))
        primary=SimpleNamespace(pending=('budget',));calls=[]
        attempt=run_with_legacy_fallback(lambda:primary,lambda:calls.append('executed') or 'reference-result')
        self.assertEqual((attempt.active_engine,attempt.primary,attempt.result),('legacy',primary,'reference-result'))
        self.assertEqual(calls,['executed'])
        with self.assertRaises(RuntimeError):run_with_legacy_fallback(lambda:primary,None)


if __name__=='__main__':unittest.main()
