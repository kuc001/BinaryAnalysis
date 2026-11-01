"""Boundary regressions that prevent false exactness and silent data loss."""
import unittest
from dataclasses import replace
from test_p5_memory import engine
from emtaint.core import Endian,Completeness
from emtaint.core.contracts import (ValueType,ValueRef,Constant,SemanticBudgets,UnsupportedSemantics)
from emtaint.memory import SymbolicOp,ObjectLifetime,WriteMemory,AliasResult,AliasKind,UpdateKind
from emtaint.core.contracts import Assessment
from emtaint.memory.cir import MemoryEffectInterpreter
from emtaint.memory.policies import BudgetExceeded
from emtaint.memory.query_port import QueryBudget
from emtaint.ir.canonical import Compute,ValueOp,StoreEffect,LoadEffect
from emtaint.compat.sse import LegacyAstPacket
from emtaint.solver.memory_lowering import MemorySolverLowering
from emtaint.solver.lowering import LoweringRequest,LoweringStatus


class BoundaryTests(unittest.TestCase):
    def test_write_port_preserves_caller_weak_update(self):
        e,r=engine();loc=e.location(r,0,8,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,e.dag.constant(7,8,'o0'),origin='o0')
        weak=WriteMemory(m,loc.id,e.dag.constant(9,8,'o0'),None,UpdateKind.WEAK,
            AliasResult(AliasKind.MAY,(),Assessment()),'o0')
        result=e.write(weak)
        self.assertEqual(e.versions[result.state].definition.update,UpdateKind.WEAK)
        self.assertEqual(set(e.possible_constants(e.load(result.state,loc))),{7,9})

    def test_write_port_requires_unique_and_exact_coverage_for_strong(self):
        e,r=engine();loc=e.location(r,0,8,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,e.dag.constant(7,8,'o0'),origin='o0')
        must=e.resolve_alias(m,loc,loc)
        weak=WriteMemory(m,loc.id,e.dag.constant(9,8,'o0'),None,UpdateKind.WEAK,must,'o0',False,True)
        state=e.write(weak).state
        self.assertEqual(set(e.possible_constants(e.load(state,loc))),{7,9})
        self.assertEqual(e.snapshot().assessment.precision.value,'over_approx')

    def test_cir_self_update_keeps_pointer_provenance_and_order(self):
        e,r=engine();p=ValueRef('p',ValueType.pointer(32));v=ValueRef('v',ValueType.bv(32))
        h=MemoryEffectInterpreter(e,{p.id:e.dag.symbol('p',p.type,'o0')},{p.id:(r,0)})
        effects=(Compute('o0',p,ValueOp.ADD,(p,Constant(8,ValueType.bv(32)))),
            StoreEffect('o0',p,Constant(99,ValueType.bv(32)),32,Endian.LITTLE,Constant(True,ValueType.boolean())),
            LoadEffect('o0',v,p,32,Endian.LITTLE,Constant(True,ValueType.boolean())))
        h.run(effects);self.assertEqual(h.addresses[p.id],(r,8))
        self.assertEqual(e.constant_value(h.values[v.id]),99)
        self.assertEqual(e.snapshot().assessment.status,Completeness.COMPLETE)

    def test_initial_byte_identity_survives_width_and_endian_views(self):
        e,r=engine();whole=e.location(r,0,16,Endian.LITTLE,'o0')
        byte=e.location(r,1,8,Endian.BIG,'o0')
        read=e.load(e.initial,whole);high=e.dag.operation(SymbolicOp.EXTRACT,ValueType.bv(8),(read,),'o0',(15,8))
        other=e.load(e.initial,byte)
        a,_=e.resolve(high);b,_=e.resolve(other)
        # Both contain the same initial-byte symbol, even when an Extract of a
        # Concat is retained instead of algebraically simplified.
        def symbols(ref):
            out=set();stack=[ref]
            while stack:
                n=e.dag.nodes[stack.pop()]
                if n.op==SymbolicOp.SYMBOL:out.add(n.value)
                stack.extend(n.operands)
            return out
        self.assertTrue(symbols(b)<=symbols(a))

    def test_long_definition_history_stops_explicitly(self):
        e,r=engine();m=e.initial
        for offset in range(70):
            loc=e.location(r,offset,8,Endian.LITTLE,'o0')
            m=e.store(m,loc,e.dag.constant(offset,8,'o0'),origin='o0')
        read=e.load(m,e.location(r,0,8,Endian.LITTLE,'o0'))
        self.assertEqual(e.constant_value(read),0)
        result=MemorySolverLowering().lower(LoweringRequest(e.snapshot(),read,budget=QueryBudget(max_steps=5)))
        self.assertEqual(result.status,LoweringStatus.INCOMPLETE);self.assertIsNone(result.query)

    def test_invalid_legacy_vsa_packet_is_rejected(self):
        data={'op':'BVS','width':32,'args':['x',1,10,2,False,False,None]}
        with self.assertRaises(ValueError):LegacyAstPacket.from_dict(data)

    def test_freed_object_read_never_reports_exact_complete(self):
        e,r=engine();e.object_facts[r.object_id]=replace(e.object_facts[r.object_id],lifetime=ObjectLifetime.FREED)
        loc=e.location(r,0,8,Endian.LITTLE,'o0')
        e.load(e.initial,loc)
        self.assertEqual(e.snapshot().assessment.status,Completeness.INCOMPLETE)

    def test_alias_context_state_and_facts_budgets_remain_explicit(self):
        e,r=engine(replace(SemanticBudgets(),heap_cells=1))
        e.location(r,0,8,Endian.LITTLE,'o0')
        with self.assertRaises(BudgetExceeded): e.location(r,1,8,Endian.LITTLE,'o0')
