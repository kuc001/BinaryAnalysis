import unittest
from dataclasses import replace
import test_p7_demand as demand_fixtures
from emtaint.core.contracts import ValueRef,ValueType,Constant
from emtaint.ir.canonical import CIRBlock,LoadEffect,Compute,ValueOp
from emtaint.analysis.taint.demand import LegacyTaintDemand
from emtaint.analysis.taint.evidence import focused_snapshot
from emtaint.memory import Deref,Offset
from emtaint.analysis.taint.demand import TaintDependency
from emtaint.analysis.taint.tables import TableRoot
from emtaint.analysis.taint.query_worklist import TaintQuery
from emtaint.analysis.dataflow.legacy_demand import DemandLimit


class HashTableTests(unittest.TestCase):
    def writer(self):
        d,bid=demand_fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),('hsearch_r',(0x1000,0x1000,1,0x2000,0x2010),True)))
        summary=d.analyze()
        root,dependencies=next((root,deps) for root,deps in summary.tables if any(dep.kind=='source' for dep in deps))
        self.assertEqual((root.kind,root.value),('global',0x2010))
        snapshot=focused_snapshot(d.port.engine.snapshot())
        self.assertTrue(snapshot.taint_facts)
        graph=d.port.engine.graphs[d.port.engine.facts[-1].graph]
        self.assertEqual(sum(isinstance(edge.label,Deref) for edge in graph.edges),2)
        return {root:tuple(dep for dep in dependencies if dep.kind=='source')}

    def reader(self,bank,*,data_field):
        d,bid=demand_fixtures.TaintDemandTests().make((('hsearch_r',(0x1000,0,0,0x2000,0x2010),True),('system',(0,),True)))
        original=d.function.blocks[0].effects;t=ValueType.bv(32);ptr=ValueType.pointer(32);truth=Constant(True,ValueType.boolean())
        entry=ValueRef('entry',t);offset=ValueRef('entry-data-offset',t);address=ValueRef('entry-data-address',ptr);value=ValueRef('data',t)
        effects=[original[0],LoadEffect('o1',entry,Constant(0x2000,ptr),32,d.port.engine.architecture.endian,truth)]
        values=(entry,)
        if data_field:
            effects.extend((Compute('o1',offset,ValueOp.ADD,(entry,Constant(4,t))),
                Compute('o1',address,ValueOp.ADD,(Constant(0,ptr),offset)),
                LoadEffect('o1',value,address,32,d.port.engine.architecture.endian,truth)))
            values=(entry,offset,address,value)
        effects.append(replace(original[1],arguments=(value if data_field else entry,)))
        function=replace(d.function,values=values,blocks=(CIRBlock(bid,tuple(effects)),))
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,tables=bank)
        return d,d.analyze()

    def test_insert_then_find_preserves_source_and_both_return_indirections(self):
        bank=self.writer();d,summary=self.reader(bank,data_field=True)
        self.assertTrue(any(dep.kind=='source' for sink in summary.sinks for dep in sink.dependencies))
        self.assertTrue(d.table_state.reads);self.assertTrue(d.port.engine.snapshot().taint_facts)
        _,plain=self.reader(bank,data_field=False)
        self.assertFalse(any(dep.kind=='source' for sink in plain.sinks for dep in sink.dependencies))

    def test_missing_global_source_is_a_deferred_hash_requirement(self):
        _,summary=self.reader({},data_field=True)
        self.assertTrue(any(dep.kind=='hash' for sink in summary.sinks for dep in sink.dependencies))

    def test_find_without_local_sink_records_retptr_data_path_only(self):
        bank=self.writer();d,summary=self.reader(bank,data_field=False)
        self.assertTrue(d.table_state.find_projections)
        binding=next(iter(d.table_state.find_projections.values()))
        graph=d.port.engine.graphs[binding.fact.graph]
        labels=[edge.label for edge in graph.edges]
        self.assertEqual(sum(isinstance(label,Deref) for label in labels),2)
        self.assertTrue(any(isinstance(label,Offset) and label.delta_bytes==4 for label in labels))
        self.assertFalse(any(dep.kind=='source' for sink in summary.sinks for dep in sink.dependencies))
        missing,_=self.reader({},data_field=False)
        self.assertFalse(missing.table_state.find_projections)

    def test_table_source_survives_later_unrelated_global_binding_limit(self):
        d,bid=demand_fixtures.TaintDemandTests().make((('system',(0x1000,),True),))
        call=d.function.blocks[0].effects[0]
        root=TableRoot(d.port.scope.function.binary.sha256,'global',0x2010)
        sources=(TaintDependency('source',0),TaintDependency('global',0x2000))
        original=d.bind_dependencies
        def limited(dependencies,*args,**kwargs):
            if any(item.kind=='global' for item in dependencies):
                raise DemandLimit('Injected unrelated global expression budget',dimension='steps')
            return original(dependencies,*args,**kwargs)
        d.bind_dependencies=limited
        query=TaintQuery('table-fixture','table',bid,0,call,(root,sources))
        with self.assertRaises(DemandLimit):d.execute_query(query)
        self.assertIn(root,d.table_state.outputs)
        self.assertTrue(any(item.kind=='source' and item.value==0 for item in d.table_state.outputs[root]))
        self.assertTrue(any(item.kind=='unknown' and 'table' in str(item.value) for item in d.table_state.outputs[root]))
        reader_d,reader=self.reader({root:d.table_state.outputs[root]},data_field=True)
        self.assertTrue(any(item.kind=='unknown' for sink in reader.sinks for item in sink.dependencies))
        self.assertTrue(any('table' in reason for reason in reader_d.unknown_evidence))
