"""Actual CIR call order/source/copy/clean definitions, no Golden inputs."""
import unittest
from dataclasses import replace
from test_p3_contracts import fixture
from emtaint.core import ABI,CallSiteId,ProgramPoint,BlockId
from emtaint.core.contracts import Origin,Constant,ValueType,SemanticBudgets,ValueRef
from emtaint.ir.canonical import (CIRFunction,CIRBlock,CallEffect,CallFootprint,ExternalTarget,
    StoreEffect,Compute,ValueOp,BranchEffect,ReadRegister,RegisterSlice,LoadEffect)
from emtaint.graph import ControlFlowGraph,FlowEdge,FlowKind
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.taint.demand import (LegacyTaintDemand, TaintDependency,
    TaintProcedureSummary, SinkRequirement, DeferredFormatArgument)
from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.procedures.legacy import lookup
from emtaint.memory import SymbolicOp


class TaintDemandTests(unittest.TestCase):
    def make(self,events,*,format_data=None):
        _,fid,bid,origin,scope,arch,*_=fixture();t=ValueType.bv(32);ptr=ValueType.pointer(32)
        truth=Constant(True,ValueType.boolean());abi=ABI('fixture',('r0','r1','r2','r3'),('r0',),'sp')
        effects=[];origins=[]
        for i,event in enumerate(events):
            o=replace(origin,id='o'+str(i),point=ProgramPoint(bid,i,i*4));origins.append(o)
            if event=='clean':effects.append(StoreEffect(o.id,Constant(0x2000,ptr),Constant(0,t),32,arch.endian,truth))
            elif event[0]=='store':effects.append(StoreEffect(o.id,Constant(event[1],ptr),Constant(event[2],t),32,arch.endian,truth))
            else:
                name,args,guard=event
                effects.append(CallEffect(o.id,CallSiteId(o.point),ExternalTarget(name),tuple(Constant(a,t) for a in args),(),abi,Constant(guard,ValueType.boolean())))
        function=CIRFunction(fid,(),(CIRBlock(bid,tuple(effects)),),bid,abi)
        cfg=ControlFlowGraph(fid,frozenset((bid,)),frozenset(),bid)
        data=b'\0'*32 if format_data is None else format_data.ljust(32,b'\0')
        # Explicit format_data represents an immutable string literal. Mutable
        # runtime format storage has a separate unknown-format regression.
        engine=ImageMemoryEngine(scope,arch,tuple(origins),((0x1000,data,32,4 if format_data is not None else 6),
            (0x2000,b'\0'*32,32,6),(0x3000,b'\0'*32,32,6)),SemanticBudgets(),initial_policy='legacy-loader-snapshot')
        port=MemoryRuntimePort(engine);initial=legacy_entry(CIRAccurateDataFlow(port))
        return LegacyTaintDemand(function,port,cfg,initial),bid

    def test_source_copy_reaches_destination_using_memory_alias_and_source_facts(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),('strcpy',(0x2000,0x1000),True)))
        pointer=d.port.constant(0x2000,ValueType.bv(32),'o1')
        deps=d.buffer(bid,2,pointer,'o1')
        self.assertTrue(any(x.kind=='source' and x.value==0 and x.constraints==(16,) for x in deps))
        self.assertTrue(d.port.engine.facts);self.assertGreater(d.port.calls['resolve_alias'],0)
        self.assertGreater(len(d.port.engine.versions),1)

    def test_vsnprintf_string_va_list_store_reaches_destination(self):
        # Preserve the old helper's unusual offset % arch.bytes selector:
        # an aligned +4 Store on ARM32 still selects format position zero.
        d,_=self.make((('recv',(0,0x3008,24,0),True),('store',0x2004,0x3008),
            ('vsnprintf',(0x2018,16,0x1000,0x2000),True),('system',(0x2018,),True)),format_data=b'%s\0')
        sink=next(item for item in d.analyze().sinks if item.name=='system')
        sources=[dep for dep in sink.dependencies if dep.kind=='source']
        self.assertTrue(sources)
        self.assertIn(16,sources[0].constraints)

    def test_vsnprintf_non_string_va_list_store_does_not_propagate(self):
        d,_=self.make((('recv',(0,0x3008,24,0),True),('store',0x2004,0x3008),
            ('vsnprintf',(0x2018,16,0x1000,0x2000),True),('system',(0x2018,),True)),format_data=b'%d\0')
        sink=next(item for item in d.analyze().sinks if item.name=='system')
        self.assertFalse(any(dep.kind=='source' for dep in sink.dependencies))

    def test_vsnprintf_va_list_store_uses_proved_entry_frame_offset(self):
        import test_p6_demand as legacy_fixture
        d,bid=self.make((('recv',(0,0x3008,24,0),True),('store',0x2004,0x3008),
            ('vsnprintf',(0x2018,16,0x1000,0x2000),True),
            ('system',(0x2018,),True)),format_data=b'%s\0')
        effects=list(d.function.blocks[0].effects);t=ValueType.bv(32);ptr=ValueType.pointer(32)
        sp=ValueRef('va-entry-sp',t)
        offset=ValueRef('va-store-offset',t)
        address=ValueRef('va-store-address',ptr)
        prefix=(legacy_fixture.get('sp',sp),
            Compute('o0',offset,ValueOp.SUB,(sp,Constant(8,t))),
            Compute('o0',address,ValueOp.ADD,(Constant(0,ptr),offset)))
        effects[1]=replace(effects[1],address=address)
        arguments=list(effects[2].arguments);arguments[3]=Constant(0x7ffffff7,t)
        effects[2]=replace(effects[2],arguments=tuple(arguments))
        footprint=CallFootprint((),(),(),False,'fixture modeled call preserves SP')
        effects=[replace(effect,footprint=footprint) if isinstance(effect,CallEffect) else effect
            for effect in effects]
        function=replace(d.function,values=(sp,offset,address),
            blocks=(CIRBlock(bid,(effects[0],)+prefix+tuple(effects[1:])),))
        demand=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
        self.assertIsNone(demand.demand.local_address(address)[1])
        self.assertEqual(demand.demand.exact_stack_address(address)[1],(-8)%(1<<32))
        sink=next(item for item in demand.analyze().sinks if item.name=='system')
        self.assertTrue(any(dep.kind=='source' for dep in sink.dependencies))

    def test_deferred_vsnprintf_argument_is_selected_by_caller_format(self):
        selector=TaintDependency('format_argument',
            DeferredFormatArgument(0,0,TaintDependency('argument',1)),
            uncertain=True,unresolved_constraints=True)
        for format_data,expected in ((b'%s\0',True),(b'%d\0',False)):
            with self.subTest(format_data=format_data):
                d,bid=self.make((('recv',(0,0x3008,24,0),True),
                    ('callee',(0x1000,0x3008),True)),format_data=format_data)
                call=d.function.blocks[0].effects[1]
                dependencies=d.bind_dependencies((selector,),call,bid,1)
                self.assertEqual(any(dep.kind=='source' for dep in dependencies),expected)

    def test_unresolved_formal_format_exports_va_list_store_as_deferred_selector(self):
        d,bid=self.make((('recv',(0,0x3008,24,0),True),('store',0x2004,0x3008),
            ('vsnprintf',(0x2018,16,0x1000,0x2000),True)),format_data=b'%s\0')
        call=d.function.blocks[0].effects[2]
        d.format_string_indexes=lambda effect,rule:((),True)
        d.scalar_expression=lambda reference,block,index,origin:(TaintDependency('scalar_argument',1),)
        dependencies=d.va_list_dependencies(call,bid,2,lookup('vsnprintf'))
        selectors=[dep.value for dep in dependencies if dep.kind=='format_argument']
        self.assertTrue(selectors)
        self.assertTrue(any(selector.format_slot==1 and selector.position==0 and
            selector.dependency.kind=='source' for selector in selectors))

    def test_strstr_return_keeps_input_pointer_value_for_later_copy_destination(self):
        d,bid=self.make((('recv',(0,0x1000,64,0),True),
            ('strstr',(0x7ffffea2,0x1000),True),('strcpy',(0,0x1000),True)))
        returned=ValueRef('strstr-return',ValueType.bv(32));effects=list(d.function.blocks[0].effects)
        effects[1]=replace(effects[1],results=(returned,))
        effects[2]=replace(effects[2],arguments=(returned,effects[2].arguments[1]))
        function=replace(d.function,values=(returned,),blocks=(CIRBlock(bid,tuple(effects)),))
        demand=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
        sink=next(s for s in demand.analyze().sinks if s.name=='strcpy')
        self.assertIn(349,sink.offsets)
        self.assertTrue(any(destination.kind=='unknown' for destination in sink.destinations))

    def test_strdup_return_is_not_an_input_pointer_alias(self):
        d,bid=self.make((('strdup',(0x7ffffea2,),True),('strcpy',(0,0x1000),True)))
        returned=ValueRef('strdup-return',ValueType.bv(32));effects=list(d.function.blocks[0].effects)
        effects[0]=replace(effects[0],results=(returned,))
        effects[1]=replace(effects[1],arguments=(returned,effects[1].arguments[1]))
        function=replace(d.function,values=(returned,),blocks=(CIRBlock(bid,tuple(effects)),))
        demand=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
        sink=next(s for s in demand.analyze().sinks if s.name=='strcpy')
        self.assertNotIn(349,sink.offsets)

    def test_first_legacy_ddg_iteration_is_a_may_destination_with_unknown_tail(self):
        d,_=self.make((('strcpy',(0,0x1000),True),));p=d.port;t=ValueType.bv(32)
        index=p.symbol('i',t,'o0');stride=p.constant(3,t,'o0')
        delta=p.operation(SymbolicOp.MUL,t,(index,stride),'o0')
        base=p.constant(0x7ffffe9f,t,'o0')
        pointer=p.operation(SymbolicOp.ADD,t,(base,delta),'o0')
        offsets,destinations=d.destination(pointer,'o0')
        self.assertEqual(offsets,(349,))
        self.assertTrue(any(item.kind=='unknown' for item in destinations))
        unresolved=p.symbol('unresolved-base',t,'o0')
        pointer=p.operation(SymbolicOp.ADD,t,(unresolved,delta),'o0')
        offsets,destinations=d.destination(pointer,'o0')
        self.assertFalse(offsets)
        self.assertTrue(any(item.kind=='unknown' for item in destinations))

    def test_real_ddg_recurrence_keeps_base_and_first_iteration(self):
        import test_p6_demand as old_fixture
        t=ValueType.bv(32);a=ValueRef('loop-a',t);b=ValueRef('loop-b',t);out=ValueRef('loop-out',t)
        old,function,cfg=old_fixture.DemandTests().make((
            (old_fixture.put('r4',Constant(0x7ffffe9f,t)),),
            (old_fixture.get('r4',a),Compute('o0',b,ValueOp.ADD,(a,Constant(3,t))),old_fixture.put('r4',b)),
            (old_fixture.get('r4',out),)),((0,1),(1,1),(1,2)))
        demand=LegacyTaintDemand(function,old.port,cfg,old.initial)
        resolutions=[demand.destination(reference,'o0') for reference in demand.demand.value(out)]
        self.assertIn(352,tuple(offset for offsets,_ in resolutions for offset in offsets))
        self.assertIn(349,tuple(offset for offsets,_ in resolutions for offset in offsets))
        self.assertTrue(any(item.kind=='unknown' for _,destinations in resolutions for item in destinations))

    def test_false_source_and_source_after_sink_do_not_create_network_flow(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),False),))
        pointer=d.port.constant(0x1000,ValueType.bv(32),'o0')
        self.assertFalse(any(x.kind=='source' for x in d.buffer(bid,1,pointer,'o0')))
        d,bid=self.make((('recv',(0,0x1000,16,0),True),))
        pointer=d.port.constant(0x1000,ValueType.bv(32),'o0')
        self.assertFalse(any(x.kind=='source' for x in d.buffer(bid,0,pointer,'o0')))

    def test_source_buffer_covers_interior_bytes_and_zero_length_is_not_a_write(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),))
        pointer=d.port.constant(0x1004,ValueType.bv(32),'o0')
        self.assertTrue(any(x.kind=='source' for x in d.buffer(bid,1,pointer,'o0')))
        d,bid=self.make((('recv',(0,0x1000,0,0),True),))
        pointer=d.port.constant(0x1000,ValueType.bv(32),'o0')
        self.assertFalse(any(x.kind=='source' for x in d.buffer(bid,1,pointer,'o0')))

    def test_strong_clean_definition_kills_the_corresponding_dependency(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),('strcpy',(0x2000,0x1000),True),'clean'))
        pointer=d.port.constant(0x2000,ValueType.bv(32),'o2')
        self.assertFalse(any(x.kind=='source' for x in d.buffer(bid,3,pointer,'o2',byte_access=True)))
        # A byte definition alone does not prove the entire source buffer clean.
        self.assertTrue(any(x.kind=='source' for x in d.buffer(bid,3,pointer,'o2')))

    def test_budget_after_completed_sink_retains_flow_and_frontier(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),('system',(0x1000,),True),('system',(0x1000,),True)))
        tick=d.tick
        def stop_after_first_sink():
            if d.completed_sinks:raise DemandLimit('injected exhausted budget')
            tick()
        d.tick=stop_after_first_sink
        result=d.analyze()
        self.assertEqual(len(result.sinks),1)
        self.assertTrue(any(dep.kind=='source' for dep in result.sinks[0].dependencies))
        self.assertTrue(d.port.engine.facts)
        self.assertEqual(result.pending[-1][0],'o2')
        self.assertIn('DemandLimit',result.pending[-1][1])

    def test_format_query_reuses_same_initial_memory_without_repeated_reads(self):
        d,bid=self.make((('sprintf',(0x2000,0x1000,0x2000),True),))
        call=d.function.blocks[0].effects[0];rule=lookup('sprintf')
        first=d.format_arguments(call,rule);reads=d.port.calls['read']
        self.assertEqual(d.format_arguments(call,rule),first)
        self.assertEqual(d.port.calls['read'],reads)
        self.assertGreater(reads,0)

    def guarded(self,name,operation,bound):
        d,bid=self.make((('recv',(0,0x1000,128,0),True),(name,(0x1000,0x2000),True)))
        original=d.function;ret=ValueRef('ret',ValueType.bv(32));condition=ValueRef('condition',ValueType.boolean())
        effects=list(original.blocks[0].effects);effects[1]=replace(effects[1],results=(ret,))
        yes=BlockId(bid.function,0x20);no=BlockId(bid.function,0x40)
        origin=d.port.engine.origins[0]
        d.port.engine.origins+=tuple(replace(origin,id='o'+str(i),point=ProgramPoint(bid,i,i*4)) for i in (2,3))
        effects.extend((Compute('o2',condition,operation,(ret,Constant(bound,ValueType.bv(32)))),BranchEffect('o3',condition,yes,no)))
        function=replace(original,values=(ret,condition),blocks=(CIRBlock(bid,tuple(effects)),CIRBlock(yes,()),CIRBlock(no,())))
        cfg=ControlFlowGraph(bid.function,frozenset((bid,yes,no)),frozenset((FlowEdge(bid,yes,FlowKind.TRUE),FlowEdge(bid,no,FlowKind.FALSE))),bid)
        return LegacyTaintDemand(function,d.port,cfg,d.demand.initial),yes,no

    def test_strlen_guard_attaches_bound_only_to_correct_branch(self):
        d,yes,no=self.guarded('strlen',ValueOp.ULT,32)
        pointer=d.port.constant(0x1000,ValueType.bv(32),'o2')
        positive=[x for x in d.buffer(yes,0,pointer,'o2') if x.kind=='source']
        negative=[x for x in d.buffer(no,0,pointer,'o2') if x.kind=='source']
        self.assertEqual(positive[0].constraints,(32,));self.assertTrue(positive[0].guards)
        self.assertEqual(negative[0].constraints,(128,))

    def test_strcmp_equal_zero_uses_old_path_filter_without_global_clean_fact(self):
        d,yes,no=self.guarded('strcmp',ValueOp.EQ,0)
        pointer=d.port.constant(0x1000,ValueType.bv(32),'o2')
        self.assertFalse(any(x.kind=='source' for x in d.buffer(yes,0,pointer,'o2')))
        self.assertTrue(any(x.kind=='source' for x in d.buffer(no,0,pointer,'o2')))
        other=d.port.constant(0x1010,ValueType.bv(32),'o2')
        self.assertTrue(any(x.kind=='source' for x in d.buffer(yes,0,other,'o2')))

    def test_stricmp_equal_zero_filters_tainted_second_argument_only_on_equal_edge(self):
        d,yes,no=self.guarded('stricmp',ValueOp.EQ,0)
        original=d.function
        effects=list(original.blocks[0].effects)
        source=effects[0]
        effects[0]=replace(source,arguments=source.arguments[:1]+(Constant(0x2000,ValueType.bv(32)),)+source.arguments[2:])
        function=replace(original,blocks=(CIRBlock(original.entry,tuple(effects)),)+original.blocks[1:])
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
        pointer=d.port.constant(0x2000,ValueType.bv(32),'o2')
        self.assertFalse(any(x.kind=='source' for x in d.buffer(yes,0,pointer,'o2')))
        self.assertTrue(any(x.kind=='source' for x in d.buffer(no,0,pointer,'o2')))

    def test_actual_file_and_socket_handle_lineage_is_retained_on_source(self):
        for socket in (False,True):
            events=((('accept',(0,0,0),True),('fdopen',(0,0x1000),True)) if socket else (('fopen',(0x1000,0x1000),True),))
            events+=(('fread',(0x2000,1,16,0),True),('system',(0x2000,),True))
            d,bid=self.make(events);effects=list(d.function.blocks[0].effects);refs=[]
            for index in range(2 if socket else 1):
                ref=ValueRef('handle'+str(index),ValueType.bv(32));refs.append(ref)
                effects[index]=replace(effects[index],results=(ref,))
                if index:effects[index]=replace(effects[index],arguments=(refs[index-1],effects[index].arguments[1]))
            source_index=2 if socket else 1
            effects[source_index]=replace(effects[source_index],arguments=effects[source_index].arguments[:3]+(refs[-1],))
            function=replace(d.function,values=tuple(refs),blocks=(CIRBlock(bid,tuple(effects)),))
            d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
            result=d.analyze();deps=[dep for sink in result.sinks for dep in sink.dependencies if dep.kind=='source']
            self.assertTrue(deps)
            kinds={kind for dep in deps for kind,value in dep.handles}
            self.assertIn('file',kinds);self.assertEqual('socket' in kinds,socket)

    def test_popen_return_is_a_legacy_file_stream_and_remains_a_command_sink(self):
        d,bid=self.make((('popen',(0x1000,0x1000),True),
            ('fgets',(0x2000,16,0),True),('system',(0x2000,),True)))
        effects=list(d.function.blocks[0].effects)
        returned=ValueRef('popen-stream',ValueType.bv(32))
        effects[0]=replace(effects[0],results=(returned,))
        effects[1]=replace(effects[1],arguments=effects[1].arguments[:2]+(returned,))
        function=replace(d.function,values=(returned,),blocks=(CIRBlock(bid,tuple(effects)),))
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
        summary=d.analyze()
        self.assertTrue(any(sink.name=='popen' and sink.kind=='command' for sink in summary.sinks))
        sources=(dep for sink in summary.sinks for dep in sink.dependencies if dep.kind=='source')
        self.assertTrue(any(('file',0) in dep.handles for dep in sources))
        returned_sse=d.demand.value(returned)[0]
        zero=d.port.constant(0,ValueType.bv(32),'o2')
        from emtaint.memory import SymbolicOp
        same_stream=d.port.operation(SymbolicOp.ADD,ValueType.bv(32),(returned_sse,zero),'o2')
        self.assertEqual(d.handle(same_stream),(('file',0),))
        copied_zero=d.port.operation(SymbolicOp.COPY,ValueType.bv(32),(zero,),'o2')
        same_stream=d.port.operation(SymbolicOp.ADD,ValueType.bv(32),(returned_sse,copied_zero),'o2')
        self.assertEqual(d.handle(same_stream),(('file',0),))
        same_stream=d.port.operation(SymbolicOp.SUB,ValueType.bv(32),(returned_sse,zero),'o2')
        self.assertEqual(d.handle(same_stream),(('file',0),))

    def test_incomplete_callee_is_an_unknown_memory_effect(self):
        from emtaint.analysis.taint.demand import TaintProcedureSummary
        from emtaint.ir.canonical import DirectTarget
        from emtaint.core import FunctionId
        d,bid=self.make((('ignored',(0x1000,),True),))
        call=replace(d.function.blocks[0].effects[0],target=DirectTarget(FunctionId(bid.function.binary,0x200)))
        function=replace(d.function,blocks=(CIRBlock(bid,(call,)),))
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,summaries={0x200:TaintProcedureSummary(0x200,pending=('original ignored function',))})
        pointer=d.port.constant(0x1000,ValueType.bv(32),'o0')
        self.assertTrue(any(dep.kind=='unknown' for dep in d.buffer(bid,1,pointer,'o0')))

    def test_formal_offset_and_inherited_constraints_survive_caller_binding(self):
        from emtaint.analysis.taint.demand import TaintDependency
        d,bid=self.make((('strncmp',(0,0,0),True),))
        base=d.port.symbol('argument:0',ValueType.bv(32),'o0')
        shifted=d.port.operation(ValueOp.ADD,ValueType.bv(32),(base,d.port.constant(8,ValueType.bv(32),'o0')),'o0')
        self.assertEqual([dep.offset for dep in d.buffer(bid,0,shifted,'o0') if dep.kind=='argument'],[8])
        d,bid=self.make((('recv',(0,0x1008,128,0),True),('strcpy',(0x1000,0x2000),True)))
        call=d.function.blocks[0].effects[1]
        result=d.bind_dependencies((TaintDependency('argument',0,constraints=(32,),guards=(('guard','lt',32),),offset=8),),call,bid,1)
        source=next(dep for dep in result if dep.kind=='source')
        self.assertEqual(source.constraints,(32,));self.assertEqual(source.guards,(('guard','lt',32),))

    def test_imported_callee_source_materializes_caller_scoped_apg_fact(self):
        from emtaint.analysis.taint.demand import TaintDependency
        d,bid=self.make((('callee',(0x1000,),True),))
        call=d.function.blocks[0].effects[0]
        result=d.bind_dependencies((TaintDependency('source',0x900,guards=(('callee-guard','lt',32),)),),call,bid,0)
        self.assertEqual(result[0].value,0x900)
        fact=d.port.engine.facts[0]
        self.assertEqual(fact.context,d.port.scope.context)
        self.assertIn(fact.memory_version,d.port.engine.versions)
        self.assertIn(fact.graph,d.port.engine.graphs)
        self.assertEqual(fact.origin,call.origin)
        self.assertTrue(any('callee-guard' in text for text in fact.provenance))
        d.bind_dependencies((TaintDependency('source',0x900),),call,bid,0)
        self.assertEqual(len(d.port.engine.facts),1)

    def test_two_callers_bind_one_formal_sink_without_source_leakage(self):
        """One detached callee summary must specialize at each actual caller."""
        from emtaint.ir.canonical import DirectTarget
        from emtaint.core import FunctionId

        sink=SinkRequirement(0x200,0x204,'system','command',(),
            (TaintDependency('argument',0),),'callee-sink')
        summary=TaintProcedureSummary(0x200,sinks=(sink,))
        source_results=[];source_paths=[]
        for events in ((('recv',(0,0x1000,16,0),True),('callee',(0x1000,),True)),
                       (('callee',(0x1000,),True),)):
            d,bid=self.make(events)
            effects=list(d.function.blocks[0].effects)
            call=effects[-1]
            effects[-1]=replace(call,target=DirectTarget(FunctionId(bid.function.binary,0x200)))
            function=replace(d.function,blocks=(CIRBlock(bid,tuple(effects)),))
            caller=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,
                summaries={0x200:summary})
            result=caller.analyze()
            inherited=next(row for row in result.sinks if row.site==0x204)
            source_results.append({dep.value for dep in inherited.dependencies if dep.kind=='source'})
            source_paths.append({(dep.uncertain,dep.path[-1]) for dep in inherited.dependencies if dep.kind=='source'})
        self.assertEqual(source_results,[{0},set()])
        self.assertEqual(source_paths,[{(True,4)},set()])
        self.assertEqual(summary.sinks,(sink,))

    def test_unsupported_value_is_an_unknown_dependency_not_clean(self):
        d,bid=self.make((('strncmp',(0,0,0),True),))
        value=d.port.unknown(ValueType.bv(32),'o0','unsupported helper')
        result=d.expression(value,bid,0,'o0')
        self.assertEqual(result[0].kind,'unknown')
        self.assertIn('unsupported helper',result[0].value)

    def test_unknown_join_keeps_known_sources_and_all_frontier_evidence(self):
        from emtaint.analysis.taint.demand import TaintDependency
        d,bid=self.make((('strncmp',(0,0,0),True),))
        source=TaintDependency('source',0x900)
        values=d.union(((TaintDependency('unknown','unresolved store A'),source),(TaintDependency('unknown','unresolved store B'),)))
        self.assertEqual(len(values),2);self.assertIn(source,values)
        self.assertEqual(d.unknown_evidence,{'unresolved store A','unresolved store B'})

    def test_symbolic_source_length_is_resolved_from_real_caller_arguments(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),))
        length=ValueRef('source-length',ValueType.bv(32));call=d.function.blocks[0].effects[0]
        origin=d.port.engine.origins[0]
        read_origin=replace(origin,id='read-length')
        d.port.engine.origins+=(read_origin,)
        read=ReadRegister(read_origin.id,length,RegisterSlice('r2',0,32,32))
        call=replace(call,arguments=call.arguments[:2]+(length,)+call.arguments[3:])
        function=replace(d.function,values=(length,),blocks=(CIRBlock(bid,(read,call)),))
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
        pointer=d.port.constant(0x1000,ValueType.bv(32),'o0')
        source=next(dep for dep in d.buffer(bid,2,pointer,'o0') if dep.kind=='source')
        self.assertTrue(source.recipes);self.assertEqual(source.constraints,())
        caller,bid=self.make((('callee',(0,0x2000,39999,0),True),))
        bound=caller.bind_constraints(source,caller.function.blocks[0].effects[0])
        self.assertEqual(bound.constraints,(39999,));self.assertEqual(bound.recipes,())

    def test_inherited_length_survives_later_buffer_binding_limit(self):
        from emtaint.analysis.taint.demand import TaintDependency,SinkRequirement
        d,bid=self.make((('callee',(0x1000,),True),))
        call=d.function.blocks[0].effects[0]
        sink=SinkRequirement(0x400,0x404,'strncpy','copy',(32,),
            (TaintDependency('source',0),),'o0',weak_kind='copy_length',
            length_dependencies=(TaintDependency('source',1),))
        original=d.bind_dependencies
        def limited(dependencies,*args,**kwargs):
            if any(dep.kind=='source' and dep.value==0 for dep in dependencies):
                raise DemandLimit('Injected buffer alternative budget',dimension='alternatives')
            return original(dependencies,*args,**kwargs)
        d.bind_dependencies=limited
        bound=d.bind_sink(sink,call,bid,0)
        self.assertTrue(any(dep.kind=='source' and dep.value==1 for dep in bound.length_dependencies))
        self.assertTrue(any(dep.kind=='unknown' for dep in bound.dependencies))
        self.assertTrue(d.pending)

    def test_inherited_buffer_survives_length_binding_limit(self):
        from emtaint.analysis.taint.demand import TaintDependency,SinkRequirement
        d,bid=self.make((('callee',(0x1000,),True),))
        call=d.function.blocks[0].effects[0]
        sink=SinkRequirement(0x400,0x404,'strncpy','copy',(32,),
            (TaintDependency('source',0),),'o0',weak_kind='copy_length',
            length_dependencies=(TaintDependency('source',1),))
        original=d.bind_dependencies
        def limited(dependencies,*args,**kwargs):
            if any(dep.kind=='source' and dep.value==1 for dep in dependencies):
                raise DemandLimit('Injected length alternative budget',dimension='alternatives')
            return original(dependencies,*args,**kwargs)
        d.bind_dependencies=limited
        bound=d.bind_sink(sink,call,bid,0)
        self.assertTrue(any(dep.kind=='source' and dep.value==0 for dep in bound.dependencies))
        self.assertTrue(any(dep.kind=='unknown' for dep in bound.length_dependencies))
        self.assertTrue(d.pending)

    def test_local_alternative_limit_does_not_abandon_later_source_sink(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),('system',(0x1000,),True),('system',(0x1000,),True)))
        original=d.buffer;calls=[]
        def limited(*args,**kwargs):
            calls.append(1)
            if len(calls)==1:raise DemandLimit('local expression product',dimension='alternatives')
            return original(*args,**kwargs)
        d.buffer=limited;result=d.analyze()
        self.assertTrue(result.pending)
        self.assertEqual(len(result.sinks),2)
        self.assertTrue(any(dep.kind=='unknown' for sink in result.sinks for dep in sink.dependencies))
        self.assertTrue(any(dep.kind=='source' for sink in result.sinks for dep in sink.dependencies))

    def test_local_alternative_cap_keeps_sources_observed_before_overflow(self):
        from emtaint.analysis.taint.demand import TaintDependency
        d,bid=self.make((('system',(0x1000,),True),))
        d.max_dependencies=2
        sources=tuple(TaintDependency('source',site,guards=('g'+str(site),),uncertain=True)
            for site in (1,2,3))
        d.buffer=lambda *args,**kwargs:sources
        result=d.analyze();sink=result.sinks[0]
        self.assertEqual({dep.value for dep in sink.dependencies if dep.kind=='source'},{1,2,3})
        self.assertTrue(any(dep.kind=='unknown' for dep in sink.dependencies))
        self.assertTrue(any('Local sink binding incomplete' in str(item) for item in result.pending))

    def test_local_length_alternative_limit_keeps_buffer_sources(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),('strncpy',(0x2000,0x1000,8),True)))
        def limited(*args,**kwargs):
            d.partial_sources.add(TaintDependency('source',0xabc,uncertain=True))
            raise DemandLimit('injected length alternatives',dimension='alternatives')
        d.length_taint=limited;result=d.analyze()
        sink=next(sink for sink in result.sinks if sink.name=='strncpy')
        self.assertTrue(any(dep.kind=='source' for dep in sink.dependencies))
        self.assertFalse(any(dep.kind=='source' and dep.value==0xabc for dep in sink.dependencies))
        self.assertTrue(any(dep.kind=='source' and dep.value==0xabc
            for dep in sink.length_dependencies))
        self.assertTrue(any(dep.kind=='unknown' for dep in sink.length_dependencies))
        self.assertTrue(any('Local sink length binding incomplete' in str(item) for item in result.pending))

    def test_copy_transfer_length_limit_does_not_erase_data_source(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),
            ('strncpy',(0x2000,0x1000,8),True),('system',(0x2000,),True)))
        def limited(*args,**kwargs):
            raise DemandLimit('injected transfer length alternatives',dimension='alternatives')
        d.length_taint=limited;result=d.analyze()
        sink=next(sink for sink in result.sinks if sink.name=='system')
        self.assertTrue(any(dep.kind=='source' for dep in sink.dependencies))
        self.assertTrue(any(dep.kind=='unknown' for dep in sink.dependencies))
        self.assertTrue(any('Copy transfer length binding incomplete' in str(item) for item in result.pending))

    def test_source_loaded_then_stored_keeps_original_source_identity(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),'clean',('system',(0x2000,),True)))
        byte=ValueRef('copied-byte',ValueType.bv(8));truth=Constant(True,ValueType.boolean())
        effects=d.function.blocks[0].effects
        load=LoadEffect('o1',byte,Constant(0x1000,ValueType.pointer(32)),8,d.port.engine.architecture.endian,truth)
        store=StoreEffect('o1',Constant(0x2000,ValueType.pointer(32)),byte,8,d.port.engine.architecture.endian,truth)
        function=replace(d.function,values=(byte,),blocks=(CIRBlock(bid,(effects[0],load,store,effects[2])),))
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial)
        result=d.analyze()
        self.assertTrue(any(dep.kind=='source' and dep.value==0 for sink in result.sinks for dep in sink.dependencies))

    def test_global_limit_inside_current_query_keeps_already_found_source(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),('system',(0x1000,),True)))
        original=d.source
        def stopped(*args,**kwargs):
            original(*args,**kwargs)
            raise DemandLimit('injected global query deadline',dimension='time')
        d.source=stopped;result=d.analyze()
        self.assertTrue(result.pending)
        self.assertTrue(any(dep.kind=='source' for sink in result.sinks for dep in sink.dependencies))
        self.assertTrue(any(dep.kind=='unknown' for sink in result.sinks for dep in sink.dependencies))
        self.assertTrue(d.port.engine.facts)

    def test_system_variadic_string_and_execve_pointer_slot_use_actual_definitions(self):
        d,bid=self.make((('recv',(0,0x2000,16,0),True),('_system',(0x1000,0x2000),True)),format_data=b'echo %s\0')
        result=d.analyze()
        self.assertTrue(any(dep.kind=='source' for sink in result.sinks for dep in sink.dependencies))
        d,bid=self.make((('recv',(0,0x1000,16,0),True),'clean','clean',('execve',(0x1000,0x2000,0),True)))
        effects=list(d.function.blocks[0].effects)
        effects[1]=replace(effects[1],value=Constant(0x1000,ValueType.bv(32)))
        effects[2]=replace(effects[2],address=Constant(0x2004,ValueType.pointer(32)))
        function=replace(d.function,blocks=(CIRBlock(bid,tuple(effects)),))
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial);result=d.analyze()
        self.assertTrue(any(dep.kind=='source' for sink in result.sinks for dep in sink.dependencies))
        self.assertGreater(d.port.calls['resolve_definition'],0)

    def test_execve_without_a_corresponding_terminator_remains_unknown(self):
        d,bid=self.make((('execve',(0x1000,0x2000,0),True),))
        result=d.analyze()
        self.assertTrue(any(dep.kind=='unknown' for sink in result.sinks for dep in sink.dependencies))

    def test_strtok_saved_pointer_and_clean_redefinition_are_session_local(self):
        for clear in (False,True):
            events=(('recv',(0,0x1000,16,0),True),('strtok',(0x1000,0x2000),True))
            if clear:events+=(('strtok',(0x2000,0x2000),True),)
            events+=(('strtok',(0,0x2000),True),('system',(0,),True))
            d,bid=self.make(events);effects=list(d.function.blocks[0].effects)
            ret=ValueRef('token-return',ValueType.bv(32))
            effects[-2]=replace(effects[-2],results=(ret,));effects[-1]=replace(effects[-1],arguments=(ret,))
            function=replace(d.function,values=(ret,),blocks=(CIRBlock(bid,tuple(effects)),))
            d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial);result=d.analyze()
            sources=[dep for sink in result.sinks for dep in sink.dependencies if dep.kind=='source']
            self.assertEqual(bool(sources),not clear)

    def test_strsep_return_reads_the_pointer_cell_before_tainting_pointee(self):
        d,bid=self.make((('recv',(0,0x1000,16,0),True),'clean',('strsep',(0x2000,0x2000),True),('system',(0,),True)))
        effects=list(d.function.blocks[0].effects);ret=ValueRef('strsep-return',ValueType.bv(32))
        effects[1]=replace(effects[1],value=Constant(0x1000,ValueType.bv(32)))
        effects[2]=replace(effects[2],results=(ret,));effects[3]=replace(effects[3],arguments=(ret,))
        function=replace(d.function,values=(ret,),blocks=(CIRBlock(bid,tuple(effects)),))
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial);result=d.analyze()
        self.assertTrue(any(dep.kind=='source' for sink in result.sinks for dep in sink.dependencies))
        self.assertGreater(d.port.calls['resolve_definition'],0)

    def test_known_callee_sink_is_queried_before_an_unrelated_exhausting_copy(self):
        from emtaint.ir.canonical import DirectTarget
        from emtaint.analysis.taint.demand import TaintProcedureSummary,SinkRequirement,TaintDependency
        d,bid=self.make((('recv',(0,0x1000,16,0),True),('strcpy',(0x2000,0x1000),True),('inner',(0x1000,),True)))
        effects=list(d.function.blocks[0].effects);callee=replace(bid.function,rva=0x400)
        effects[-1]=replace(effects[-1],target=DirectTarget(callee))
        function=replace(d.function,blocks=(CIRBlock(bid,tuple(effects)),))
        sink=SinkRequirement(0x400,0x404,'system','command',(),(TaintDependency('argument',0),),'o2')
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial,summaries={0x400:TaintProcedureSummary(0x400,sinks=(sink,))})
        original=d.buffer
        def stopped(*args,**kwargs):
            if args[3]=='o1':raise DemandLimit('unrelated expensive copy deadline')
            return original(*args,**kwargs)
        d.buffer=stopped;result=d.analyze()
        self.assertTrue(result.pending)
        self.assertTrue(any(s.site==0x404 and any(dep.kind=='source' for dep in s.dependencies) for s in result.sinks))


if __name__=='__main__':unittest.main()
