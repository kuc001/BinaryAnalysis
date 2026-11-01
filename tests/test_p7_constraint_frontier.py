import unittest
import test_p7_demand as fixtures
from emtaint.core.contracts import ValueType
from emtaint.analysis.framework.summaries import ProcedureRecipe,SummaryNode
from emtaint.analysis.taint.demand import TaintDependency,ConstraintRecipe
from emtaint.procedures.legacy import lookup
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.memory import SymbolicOp


class ConstraintFrontierTests(unittest.TestCase):
    def test_large_unresolved_bound_does_not_erase_an_independent_known_source(self):
        d,bid=fixtures.TaintDemandTests().make((('system',(0x1000,),True),))
        nodes=[SummaryNode(ValueType.bv(32),'symbol',value='length-'+str(i)) for i in range(257)]
        level=list(range(len(nodes)))
        while len(level)>1:
            following=[]
            for index in range(0,len(level),2):
                if index+1==len(level):following.append(level[index]);continue
                following.append(len(nodes));nodes.append(SummaryNode(ValueType.bv(32),'add',(level[index],level[index+1])))
            level=following
        recipe=ProcedureRecipe(d.function.function_id,tuple(nodes),tuple(level),(),(),('Unknown source length',),())
        source=TaintDependency('source',0x900,recipes=(ConstraintRecipe.wrap(recipe),))
        call=d.function.blocks[0].effects[0]
        result=d.bind_dependencies((source,),call,bid,0)
        retained=next(dep for dep in result if dep.kind=='source')
        self.assertEqual(retained.value,0x900)
        self.assertTrue(retained.unresolved_constraints)
        self.assertFalse(retained.recipes)
        self.assertTrue(d.pending)

    def test_large_local_source_recipe_keeps_source_fact_and_unknown_bound(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,0,0),True),))
        call=d.function.blocks[0].effects[0];port=d.port;type_=ValueType.bv(32)
        level=[port.symbol('large-length-'+str(index),type_,'o0') for index in range(257)]
        while len(level)>1:
            level=[level[index] if index+1==len(level) else
                port.operation(SymbolicOp.ADD,type_,(level[index],level[index+1]),'o0')
                for index in range(0,len(level),2)]
        argument=d.argument
        d.argument=lambda actual,slot:(level[0],) if slot==2 else argument(actual,slot)
        d.constants=lambda actual,slots:()
        address=port.constant(0x1000,type_,'o0')
        source=d.source(call,d.location(address,'o0'),lookup('recv'))
        self.assertEqual((source.kind,source.value),('source',0))
        self.assertTrue(source.unresolved_constraints);self.assertEqual(source.recipes,())
        self.assertTrue(d.pending);self.assertTrue(port.engine.facts)

    def test_optional_handle_budget_keeps_actual_source_and_fact(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),))
        call=d.function.blocks[0].effects[0]
        def stopped(reference):raise DemandLimit('injected handle budget',dimension='query')
        d.handle=stopped
        address=d.port.constant(0x1000,ValueType.bv(32),'o0')
        with self.assertRaises(DemandLimit):d.source(call,d.location(address,'o0'),lookup('recv'))
        self.assertTrue(any(dep.kind=='source' and dep.value==0 and dep.unresolved_constraints for dep in d.query_sources))
        self.assertTrue(d.port.engine.facts)
