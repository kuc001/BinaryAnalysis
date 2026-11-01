import unittest
import test_p7_demand as fixtures
from emtaint.analysis.taint.demand import TaintDependency,ConstraintRecipe,SinkRequirement
from emtaint.analysis.dataflow.legacy_demand import DemandLimit


class SourceBeforeBoundTests(unittest.TestCase):
    def test_known_callee_source_survives_interrupted_length_and_handle_binding(self):
        d,bid=fixtures.TaintDemandTests().make((('system',(0x1000,),True),))
        class InterruptedRecipe:
            def instantiate(self,*args):raise DemandLimit('Interrupted bound, not an absent source',dimension='query')
        dependency=TaintDependency('source',0x900,handles=(('argument',2),),
            recipes=(ConstraintRecipe.wrap(InterruptedRecipe()),))
        d.active_sink=SinkRequirement(0,0,'system','command',(),(),'o0')
        with self.assertRaises(DemandLimit):d.bind_dependencies((dependency,),d.function.blocks[0].effects[0],bid,0)
        preserved=next(dep for dep in d.partial_sources if dep.kind=='source' and dep.value==0x900)
        self.assertTrue(preserved.unresolved_constraints)
        self.assertFalse(preserved.recipes)
        self.assertFalse(any(kind=='argument' for kind,value in preserved.handles))
