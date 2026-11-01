import unittest
from dataclasses import replace
from test_p3_contracts import fixture
from emtaint.core import Endian
from emtaint.core.contracts import ValueType,SemanticBudgets
from emtaint.memory.image import ImageMemoryEngine
from emtaint.memory import ReadMemory
from emtaint.memory import SymbolicOp,JoinInput
from emtaint.memory.engine import PythonMemoryEngine
from emtaint.memory.read_index import ReadIndex,records_for
from emtaint.memory.policies import BudgetExceeded
from emtaint.memory.abstract_heap import ObjectCardinality
from emtaint.compat.memory_runtime import MemoryRuntimePort


class ResolutionCacheTests(unittest.TestCase):
    def make(self):
        _,_,_,origin,scope,arch,*_=fixture()
        e=ImageMemoryEngine(scope,arch,(origin,),((0x1000,bytes(32),32,6),),SemanticBudgets(),
            initial_policy='legacy-loader-snapshot',cache_resolutions=True)
        p=MemoryRuntimePort(e);location=e.location(*e.address(0x1000),32,Endian.LITTLE,'o0')
        return e,p,location,p.constant(True,ValueType.boolean(),'o0')

    def test_read_then_definition_reuses_resolution_and_keeps_immutable_versions(self):
        e,p,loc,truth=self.make();t=ValueType.bv(32)
        first=p.write(e.initial,loc,p.constant(42,t,'o0'),truth,'o0').state
        read=p.read(first,loc,truth,'o0').value
        root,resolver=e.resolve(read);definitions=set(resolver.definitions)
        self.assertEqual(e.dag.constant_value(root),42)
        resolver.definitions.clear();resolver.memo[read]=p.constant(99,t,'o0')
        again,other=e.resolve(read)
        self.assertEqual(e.dag.constant_value(again),42);self.assertEqual(other.definitions,definitions)
        self.assertGreater(e.metrics()['resolution_cache_hits'],0)
        second=p.write(first,loc,p.constant(77,t,'o0'),truth,'o0').state
        new=p.read(second,loc,truth,'o0').value
        self.assertEqual(e.dag.constant_value(e.resolve(new)[0]),77)
        self.assertEqual(e.dag.constant_value(e.resolve(read)[0]),42)

    def test_policy_fact_and_guard_changes_cannot_reuse_incompatible_resolution(self):
        e,p,loc,truth=self.make();read=e.load(e.initial,loc,truth,'o0')
        self.assertEqual(e.dag.constant_value(e.resolve(read)[0]),0)
        self.assertIsNone(e.dag.constant_value(e.resolve(read,initial_policy='readonly-at-entry')[0]))
        self.assertEqual(e.dag.constant_value(e.resolve(read)[0]),0)
        misses=e.metrics()['resolution_cache_misses']
        e.object_facts[loc.object_id]=replace(e.object_facts[loc.object_id],cardinality=ObjectCardinality.SUMMARY)
        e.resolve(read);self.assertGreater(e.metrics()['resolution_cache_misses'],misses)
        record=next(record for record in e.reads if record.result==read)
        e.reads.append(ReadMemory(record.state,record.location,record.result,p.constant(False,ValueType.boolean(),'o0'),'o0'))
        with self.assertRaisesRegex(ValueError,'distinct guarded'):e.resolve(read)

    def test_nonconsecutive_queries_reuse_only_their_actual_read_dependencies(self):
        e,p,loc,truth=self.make()
        first=e.load(e.initial,loc,truth,'o0');other=e.location(*e.address(0x1004),32,Endian.LITTLE,'o0')
        e.resolve(first);hits=e.metrics()['resolution_cache_hits']
        second=e.load(e.initial,other,truth,'o0');e.resolve(second)
        self.assertEqual(e.dag.constant_value(e.resolve(first)[0]),0)
        self.assertGreater(e.metrics()['resolution_cache_hits'],hits)

    def test_same_length_guard_replacement_invalidates_cached_definition(self):
        e,p,loc,truth=self.make();read=e.load(e.initial,loc,truth,'o0');e.resolve(read)
        index=next(i for i,record in enumerate(e.reads) if record.result==read)
        e.reads[index]=replace(e.reads[index],guard=p.constant(False,ValueType.boolean(),'o0'))
        self.assertIsNone(e.dag.constant_value(e.resolve(read)[0]))

    def test_nested_read_guard_and_alias_facts_are_actual_cache_dependencies(self):
        e,p,loc,truth=self.make();type_=ValueType.bv(32)
        state=p.write(e.initial,loc,p.constant(42,type_,'o0'),truth,'o0').state
        read=e.load(state,loc,truth,'o0')
        plus=e.dag.operation(SymbolicOp.ADD,type_,(read,p.constant(1,type_,'o0')),'o0')
        self.assertEqual(e.dag.constant_value(e.resolve(plus)[0]),43)
        e.object_facts[loc.object_id]=replace(e.object_facts[loc.object_id],cardinality=ObjectCardinality.SUMMARY)
        self.assertIsNone(e.dag.constant_value(e.resolve(plus)[0]))
        e.object_facts[loc.object_id]=replace(e.object_facts[loc.object_id],cardinality=ObjectCardinality.SINGLETON)
        index=next(index for index,record in enumerate(e.reads) if record.result==read)
        e.reads[index]=replace(e.reads[index],guard=p.constant(False,ValueType.boolean(),'o0'))
        self.assertIsNone(e.dag.constant_value(e.resolve(plus)[0]))

    def test_index_keeps_list_order_duplicates_mutations_and_p3_snapshot(self):
        e,p,loc,truth=self.make();first=e.load(e.initial,loc,truth,'o0')
        other=e.location(*e.address(0x1004),32,Endian.LITTLE,'o0');second=e.load(e.initial,other,truth,'o0')
        actual=e.reads;expected=list(actual)
        def same():
            self.assertEqual(actual,expected)
            for ref in (first,second):self.assertEqual(records_for(actual,ref),tuple(r for r in expected if r.result==ref))
            for record in expected:self.assertEqual(record in actual,record in expected)
        actual.extend(actual);expected.extend(expected);same()
        actual.reverse();expected.reverse();same()
        actual[0]=actual[-1];expected[0]=expected[-1];same()
        del actual[1:2];del expected[1:2];same()
        actual.insert(0,actual[-1]);expected.insert(0,expected[-1]);same()
        self.assertEqual(actual.pop(),expected.pop());same()
        actual*=2;expected*=2;same()
        # Restore the actual, valid read set before P3 validation.
        e.reads=ReadIndex(tuple(dict.fromkeys(expected)))
        restored=PythonMemoryEngine.from_snapshot(e.snapshot())
        self.assertEqual(tuple(restored.reads),tuple(e.reads))

    def test_cached_and_reference_definitions_agree_for_overlap_join_and_havoc(self):
        outcomes=[]
        for cached in (False,True):
            e,p,loc,truth=self.make();e.cache_resolutions=cached
            guard=p.symbol('runtime-guard',ValueType.boolean(),'o0')
            written=p.write(e.initial,loc,p.constant(0x11223344,ValueType.bv(32),'o0'),truth,'o0').state
            part=e.location(*e.address(0x1001),8,Endian.BIG,'o0')
            overlap=p.write(written,part,p.constant(0xaa,ValueType.bv(8),'o0'),guard,'o0').state
            joined=e.join((JoinInput(written,guard),JoinInput(overlap,None)),'o0')
            havoc=e.havoc(joined,('global',),'unknown external write','o0',guard)
            rows=[]
            for state in (written,overlap,joined,havoc,written,joined):
                ref=e.load(state,loc,truth,'o0');value,resolver=e.resolve(ref)
                rows.append((e.dag.nodes[value],frozenset(resolver.definitions),tuple(resolver.assessments)))
            outcomes.append(rows)
        self.assertEqual(*outcomes)

    def test_nonconstant_read_proof_avoids_expansion_without_changing_definition_queries(self):
        e,p,loc,truth=self.make();state=e.initial
        for value in range(6):state=p.write(state,loc,p.constant(value,ValueType.bv(32),'o0'),truth,'o0').state
        unknown=e.location(None,None,32,Endian.LITTLE,'o0');read=e.load(state,unknown,truth,'o0')
        saved=e.accounting.budgets;used=e.accounting.counts['worklist_iterations']
        e.accounting.budgets=replace(saved,worklist_iterations=used+2)
        self.assertIsNone(e.constant_value(read))
        e.accounting.budgets=saved
        value,resolver=e.resolve(read)
        self.assertIsNone(e.dag.constant_value(value));self.assertIn(state,resolver.definitions)

    def test_known_initial_image_and_frame_are_excluded_from_nonconstant_proof(self):
        e,p,loc,truth=self.make();read=e.load(e.initial,loc,truth,'o0')
        self.assertEqual(e.constant_value(read),0)
        # Frame initial values can be concrete even with a summary-object fact.
        e.object_facts[loc.object_id]=replace(e.object_facts[loc.object_id],cardinality=ObjectCardinality.SUMMARY)
        e.entry_frame_inputs={loc.object_id:(p.constant(42,ValueType.bv(32),'o0'),)}
        self.assertEqual(e.constant_value(read),42)

    def test_pure_shared_dag_reuses_completed_values_under_the_same_work_budget(self):
        e,p,loc,truth=self.make();type_=ValueType.bv(32)
        shared=p.symbol('shared-input',type_,'o0')
        for index in range(16):
            shared=p.operation(SymbolicOp.MUL,type_,(shared,p.constant(3,type_,'o0')),'o0')
            shared=p.operation(SymbolicOp.ADD,type_,(shared,p.constant(index,type_,'o0')),'o0')
        roots=[p.operation(SymbolicOp.ADD,type_,(shared,p.constant(1000+index,type_,'o0')),'o0') for index in range(200)]
        e.accounting.budgets=replace(e.accounting.budgets,worklist_iterations=2000)
        for ref in roots:
            value,resolver=e.resolve(ref)
            self.assertIsNone(e.dag.constant_value(value));self.assertFalse(resolver.definitions);self.assertFalse(resolver.assessments)
        self.assertLess(e.accounting.counts['worklist_iterations'],2000)

    def test_pure_unfolded_operations_are_still_evaluated_and_mixed_read_evidence_is_retained(self):
        e,p,loc,truth=self.make();type_=ValueType.bv(32)
        one=p.constant(1,type_,'o0');two=p.constant(2,type_,'o0')
        raw=e.dag.make(type_,SymbolicOp.ADD,(one,two),'o0')
        self.assertEqual(e.constant_value(raw),3)
        read=e.load(e.initial,loc,truth,'o0');mixed=e.dag.operation(SymbolicOp.ADD,type_,(read,raw),'o0')
        value,resolver=e.resolve(mixed)
        self.assertEqual(e.dag.constant_value(value),3);self.assertIn(e.initial,resolver.definitions)
