import unittest
from dataclasses import replace
import test_p7_demand as fixtures
from emtaint.core.contracts import ValueRef,ValueType
from emtaint.ir.canonical import CIRBlock,DirectTarget
from emtaint.analysis.taint.demand import LegacyTaintDemand,TaintProcedureSummary,SinkRequirement,TaintDependency
from emtaint.procedures.legacy import legacy_copy_weak_kind
from emtaint.analysis.dataflow.legacy_demand import DemandLimit


class LengthTaintTests(unittest.TestCase):
    def test_clean_bound_preserves_copy_flow_without_marking_an_old_weak_site(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,16,0),True),('strncpy',(0x2000,0x1000,8),True)))
        sink=d.analyze().sinks[0]
        self.assertEqual(sink.weak_kind,'copy_length');self.assertEqual(sink.length_dependencies,())
        self.assertTrue(any(dep.kind=='source' for dep in sink.dependencies))
        pointer=d.port.constant(0x2000,ValueType.bv(32),'o1')
        self.assertTrue(any(dep.kind=='source' for dep in d.buffer(bid,2,pointer,'o1')))
        self.assertIsNone(legacy_copy_weak_kind(bounded=True,buffer_tainted=True,length_tainted=bool(sink.length_dependencies)))

    def test_atoi_length_tracks_its_own_source_and_old_cons_type(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,32,0),True),('atoi',(0x1000,),True),('strncpy',(0x2000,0x1000,0),True)))
        ret=ValueRef('length-result',ValueType.bv(32));effects=list(d.function.blocks[0].effects)
        effects[1]=replace(effects[1],results=(ret,));effects[2]=replace(effects[2],arguments=effects[2].arguments[:2]+(ret,))
        function=replace(d.function,values=(ret,),blocks=(CIRBlock(bid,tuple(effects)),))
        demand=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial);sink=next(s for s in demand.analyze().sinks if s.name=='strncpy')
        self.assertTrue(any(dep.kind=='source' and dep.value==0 and dep.constraint_type==4 for dep in sink.length_dependencies))

    def test_formal_scalar_bound_binds_as_a_value_not_an_unrelated_buffer(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,32,0),True),('inner',(0x2000,0x1000,8),True)))
        fid=replace(bid.function,rva=0x400);effects=list(d.function.blocks[0].effects);effects[1]=replace(effects[1],target=DirectTarget(fid))
        function=replace(d.function,blocks=(CIRBlock(bid,tuple(effects)),))
        sink=SinkRequirement(0x400,0x404,'strncpy','copy',(16,),(TaintDependency('argument',1),),'o1',
            weak_kind='copy_length',length_dependencies=(TaintDependency('scalar_argument',2),))
        summary=TaintProcedureSummary(0x400,sinks=(sink,))
        demand=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,summaries={0x400:summary})
        bound=next(s for s in demand.analyze().sinks if s.site==0x404)
        self.assertTrue(any(dep.kind=='source' for dep in bound.dependencies))
        self.assertEqual(bound.length_dependencies,())

    def test_scalar_identity_return_does_not_read_the_numeric_value_as_a_pointer(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,8,16,0),True),('identity',(8,),True)))
        fid=replace(bid.function,rva=0x400);ret=ValueRef('scalar-identity',ValueType.bv(32))
        effects=list(d.function.blocks[0].effects);effects[1]=replace(effects[1],target=DirectTarget(fid),results=(ret,))
        function=replace(d.function,values=(ret,),blocks=(CIRBlock(bid,tuple(effects)),))
        summary=TaintProcedureSummary(0x400,scalar_returns=(TaintDependency('scalar_argument',0),))
        demand=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,summaries={0x400:summary})
        value=demand.demand.value(ret)[0]
        self.assertEqual(demand.scalar_expression(value,bid,2,'o1'),())
        unavailable=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,summaries={0x400:TaintProcedureSummary(0x400)})
        self.assertEqual({dep.kind for dep in unavailable.scalar_expression(unavailable.demand.value(ret)[0],bid,2,'o1')},{'unknown'})

    def test_atoi_formal_summary_preserves_cons_type_and_converts_caller_bound(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,3,0),True),('atoi_wrapper',(0x1000,),True)))
        dep=TaintDependency('argument',0,constraint_type=4)
        result=d.bind_dependencies((dep,),d.function.blocks[0].effects[1],bid,1,scalar=True)
        source=next(value for value in result if value.kind=='source')
        self.assertEqual(source.constraint_type,4)
        self.assertEqual(source.constraints,(999,))

    def test_old_atoi_length_constraint_follows_copied_buffer(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,32,0),True),('recv',(0,0x2010,1,0),True),
            ('atoi',(0x2010,),True),('strncpy',(0x2000,0x1000,0),True)))
        ret=ValueRef('length-one-digit',ValueType.bv(32));effects=list(d.function.blocks[0].effects)
        effects[2]=replace(effects[2],results=(ret,));effects[3]=replace(effects[3],arguments=effects[3].arguments[:2]+(ret,))
        demand=LegacyTaintDemand(replace(d.function,values=(ret,),blocks=(CIRBlock(bid,tuple(effects)),)),d.port,d.cfg,d.demand.initial)
        pointer=d.port.constant(0x2000,ValueType.bv(32),'o3')
        data=[dep for dep in demand.buffer(bid,4,pointer,'o3') if dep.kind=='source']
        self.assertEqual({dep.value for dep in data},{0})
        self.assertEqual(data[0].constraints,(9,))

    def test_mixed_length_origins_do_not_impose_one_paths_bound_on_all_copies(self):
        from emtaint.procedures.legacy import uniform_copy_length_constraints
        bounded=TaintDependency('source',0x100,constraint_type=4,constraints=(9,))
        unbounded=TaintDependency('source',0x200,constraint_type=4)
        unknown=TaintDependency('unknown','unresolved length',uncertain=True,constraint_type=4)
        self.assertEqual(uniform_copy_length_constraints((bounded,)),(9,))
        self.assertEqual(uniform_copy_length_constraints((bounded,unbounded)),())
        self.assertEqual(uniform_copy_length_constraints((bounded,unknown)),())

    def test_interrupted_length_query_does_not_promote_length_only_source_to_buffer(self):
        d,bid=fixtures.TaintDemandTests().make((('strncpy',(0x2000,0x1000,8),True),))
        data=TaintDependency('source',0x900);length=TaintDependency('source',0xa00,constraint_type=4)
        d.active_sink=SinkRequirement(0,0,'strncpy','copy',(16,),(data,),'o0',weak_kind='copy_length')
        d.partial_sources={data};d.query_sources={data}
        def interrupted():
            d.partial_sources.add(length);d.query_sources.add(length)
            raise DemandLimit('injected scalar limit',dimension='query')
        with self.assertRaises(DemandLimit):d.in_length_channel(interrupted)
        self.assertEqual(d.partial_sources,{data});self.assertEqual(d.query_sources,{data})
        self.assertIn(length,d.active_sink.length_dependencies)
        self.assertNotIn(length,d.active_sink.dependencies)

    def test_may_alias_pointer_field_keeps_load_provenance_for_atoi_taint(self):
        from emtaint.ir.canonical import ReadRegister,RegisterSlice,Compute,ValueOp,StoreEffect,LoadEffect
        from emtaint.core.contracts import Constant
        d,bid=fixtures.TaintDemandTests().make((('placeholder',(),True),('getenv',(0x1000,),True),
            ('placeholder',(),True),('placeholder',(),True),('placeholder',(),True),('placeholder',(),True),('atoi',(0,),True),('strncpy',(0x2000,0,0),True)))
        pointer=ValueType.pointer(32);integer=ValueType.bv(32);truth=Constant(True,ValueType.boolean())
        context=ValueRef('context-bits',integer);base=ValueRef('context-pointer',pointer);field=ValueRef('field-pointer',pointer)
        source=ValueRef('environment-source',pointer);loaded=ValueRef('loaded-string-pointer',pointer);length=ValueRef('parsed-length',integer)
        effects=list(d.function.blocks[0].effects)
        effects[0]=ReadRegister('o0',context,RegisterSlice('r0',0,32,32))
        effects[1]=replace(effects[1],results=(source,))
        effects[2]=Compute('o2',base,ValueOp.ADD,(Constant(0,pointer),context))
        effects[3]=Compute('o3',field,ValueOp.ADD,(base,Constant(4,integer)))
        effects[4]=StoreEffect('o4',field,source,32,d.port.engine.architecture.endian,truth)
        effects[5]=LoadEffect('o5',loaded,field,32,d.port.engine.architecture.endian,truth)
        effects[6]=replace(effects[6],arguments=(loaded,),results=(length,))
        effects[7]=replace(effects[7],arguments=(effects[7].arguments[0],source,length))
        function=replace(d.function,values=(context,base,field,source,loaded,length),blocks=(CIRBlock(bid,tuple(effects)),))
        demand=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
        sink=next(value for value in demand.analyze().sinks if value.name=='strncpy')
        self.assertTrue(any(dep.kind=='source' and dep.value==4 for dep in sink.dependencies))
        self.assertTrue(any(dep.kind=='source' and dep.value==4 and dep.constraint_type==4 for dep in sink.length_dependencies))
