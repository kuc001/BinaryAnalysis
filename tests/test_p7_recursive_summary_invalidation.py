"""P7 summary invalidation on a recursive call graph."""
import unittest
from dataclasses import replace

from test_program_models import fixture
from emtaint.core import (BasicBlock, BlockId, CallKind, CallSite, CallSiteId,
    ContextId, Function, FunctionId, ProgramPoint)
from emtaint.graph import CallEdge, TargetKind
from emtaint.analysis.framework.runtime import AnalysisRuntime
from emtaint.orchestration.legacy_cir_search import callee_first


class RecursiveSummaryInvalidationTests(unittest.TestCase):
    def test_cycle_invalidates_both_members_and_keeps_unrelated_context(self):
        program, caller, callee, _, _, callee_block, forward=fixture()
        unrelated=FunctionId(program.binary,32)
        unrelated_block=BlockId(unrelated,32)
        reverse=CallSiteId(ProgramPoint(callee_block,0,callee_block.rva))
        program=replace(program,
            functions=program.functions+(Function(unrelated,'unrelated',
                (BasicBlock(unrelated_block,4),),unrelated_block),),
            callsites=program.callsites+(CallSite(reverse,CallKind.DIRECT),))
        runtime=AnalysisRuntime(program)
        runtime.add_call_edges((CallEdge(forward,callee,TargetKind.MAY,'recursive fixture'),
            CallEdge(reverse,caller,TargetKind.MAY,'recursive fixture')))
        order=callee_first((caller,callee,unrelated),runtime.session.cg)
        self.assertEqual(set(order),{caller,callee,unrelated})
        self.assertEqual(len(order),3)
        context=ContextId()
        for function in (caller,callee,unrelated):
            runtime.put('summary',function,context,'taint',(function.rva,))

        affected=runtime.invalidate_dependencies((callee,),'callee summary revision changed')

        self.assertEqual(affected,frozenset((caller,callee)))
        self.assertIsNone(runtime.get('summary',caller,context,'taint'))
        self.assertIsNone(runtime.get('summary',callee,context,'taint'))
        self.assertEqual(runtime.get('summary',unrelated,context,'taint'),(unrelated.rva,))


if __name__=='__main__':
    unittest.main()
