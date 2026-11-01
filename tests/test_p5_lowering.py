"""Pure lowering checks; actual Claripy runs are isolated in p5_native_probe."""
from dataclasses import replace
import unittest
from test_p5_memory import engine
from emtaint.core import Endian, Completeness
from emtaint.core.contracts import ValueType, Precision
from emtaint.memory import SymbolicOp, ObjectCardinality, ObjectLifetime, ReadMemory
from emtaint.memory.query_port import QueryBudget
from emtaint.solver.memory_lowering import MemorySolverLowering
from emtaint.solver.lowering import LoweringRequest, LoweringStatus
from emtaint.solver.port import Term, SolverStatus, SolverResult


class LoweringRuntimeTests(unittest.TestCase):
    def test_strong_read_to_pure_bv_and_guard_contradiction(self):
        e,r=engine();loc=e.location(r,0,32,Endian.LITTLE,'o0')
        m=e.store(e.initial,loc,e.dag.constant(42,32,'o0'),origin='o0');v=e.load(m,loc)
        lowered=MemorySolverLowering().lower(LoweringRequest(e.snapshot(),v))
        self.assertEqual(lowered.status,LoweringStatus.READY)
        self.assertEqual(lowered.query.expression,Term('BVV',32,(42,)))
        self.assertEqual(lowered.assessment.status,Completeness.COMPLETE)
        eq=e.dag.operation(SymbolicOp.EQ,ValueType.boolean(),(v,e.dag.constant(43,32,'o0')),'o0')
        result=MemorySolverLowering().lower(LoweringRequest(e.snapshot(),eq,operation='check'))
        self.assertEqual(result.query.constraints,(Term('BoolV',None,(False,)),))

    def test_guarded_alternate_no_false_read(self):
        e,r=engine();loc=e.location(r,0,8,Endian.LITTLE,'o0')
        alt=e.dag.constant(99,8,'o0');g=e.dag.boolean(False,'o0')
        value=e.guarded_load(e.initial,loc,g,alt)
        self.assertEqual(value,alt);self.assertEqual(e.reads,[])
        raw=e.load(e.initial,loc,g)
        before=e.alias_queries
        self.assertIsNone(e.constant_value(raw))
        self.assertEqual(e.alias_queries,before)

    def test_pointer_value_store_and_separate_guarded_results(self):
        e,r=engine();loc=e.location(r,0,32,Endian.LITTLE,'o0')
        pointer=e.dag.make(ValueType.pointer(32),SymbolicOp.CONSTANT,origin='o0',value=0x11223344)
        m=e.store(e.initial,loc,pointer,origin='o0')
        self.assertEqual(e.constant_value(e.load(m,loc)),0x11223344)
        false=e.load(m,loc,e.dag.boolean(False,'o0'))
        true=e.load(m,loc,e.dag.boolean(True,'o0'))
        self.assertNotEqual(false,true)
        self.assertIsNone(e.constant_value(false));self.assertEqual(e.constant_value(true),0x11223344)

    def test_unsupported_symbol_and_legacy_load_rejection(self):
        e,_=engine();value=e.dag.make(ValueType.bv(8),SymbolicOp.UNKNOWN,origin='o0',value='unsupported helper')
        result=MemorySolverLowering().lower(LoweringRequest(e.snapshot(),value))
        self.assertEqual(result.status,LoweringStatus.UNSUPPORTED);self.assertIsNone(result.query)
        with self.assertRaises(TypeError): MemorySolverLowering().lower('Load(r0,32)')

    def test_query_budget_is_incomplete_not_unsat(self):
        e,r=engine();loc=e.location(r,0,32,Endian.LITTLE,'o0');value=e.load(e.initial,loc)
        result=MemorySolverLowering().lower(LoweringRequest(e.snapshot(),value,budget=QueryBudget(max_steps=1)))
        self.assertEqual(result.status,LoweringStatus.INCOMPLETE);self.assertIsNone(result.query)
        for status in (SolverStatus.SAT,SolverStatus.UNSAT,SolverStatus.UNKNOWN,SolverStatus.TIMEOUT,SolverStatus.UNSUPPORTED):
            with self.assertRaises(TypeError): bool(SolverResult(status))

    def test_byte_oracle_randomized_strong_updates(self):
        import random
        rng=random.Random(512)
        for endian in Endian:
            e,r=engine();m=e.initial;reference={}
            for step in range(80):
                offset=rng.randrange(8);size=rng.choice((1,2,4));value=rng.randrange(1<<(size*8))
                loc=e.location(r,offset,size*8,endian,'o0')
                m=e.store(m,loc,e.dag.constant(value,size*8,'o0'),origin='o0')
                reference.update({offset+i:b for i,b in enumerate(value.to_bytes(size,endian.value))})
                if all(x in reference for x in range(4)):
                    read=e.location(r,0,32,endian,'o0')
                    expected=int.from_bytes(bytes(reference[x] for x in range(4)),endian.value)
                    self.assertEqual(e.constant_value(e.load(m,read)),expected)
