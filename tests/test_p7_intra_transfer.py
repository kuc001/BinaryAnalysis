"""P7.2 local return-source, arithmetic, register and kill propagation."""

import unittest
from dataclasses import replace

import test_p7_demand as fixtures
from emtaint.core import BlockId, CallSiteId, ProgramPoint
from emtaint.core.contracts import Constant, ValueRef, ValueType
from emtaint.ir.canonical import (
    BranchEffect, CIRBlock, Compute, LoadEffect, ReadRegister, RegisterSlice,
    RegisterWritePolicy, StoreEffect, UnknownEffect, ValueOp, WriteRegister,
)
from emtaint.graph import ControlFlowGraph, FlowEdge, FlowKind
from emtaint.analysis.taint.demand import LegacyTaintDemand


class IntraTaintTransferTests(unittest.TestCase):
    def build(self, *, overwrite: bool) -> LegacyTaintDemand:
        demand, block = fixtures.TaintDemandTests().make((
            ("getenv", (0x1000,), True), ("system", (0,), True)))
        source_call, sink_call = demand.function.blocks[0].effects
        word = ValueType.bv(32)
        truth = Constant(True, ValueType.boolean())
        returned = ValueRef("getenv-return", word)
        arithmetic = ValueRef("arithmetic", word)
        read_back = ValueRef("read-back", word)
        register = RegisterSlice("r4", 0, 32, 32)
        effects = [
            replace(source_call, results=(returned,)),
            Compute("o1", arithmetic, ValueOp.ADD,
                    (returned, Constant(0, word))),
            WriteRegister("o1", register, arithmetic,
                          RegisterWritePolicy.FULL, truth),
        ]
        if overwrite:
            effects.append(WriteRegister("o1", register, Constant(0, word),
                                         RegisterWritePolicy.FULL, truth))
        effects.extend((
            ReadRegister("o1", read_back, register),
            replace(sink_call, arguments=(read_back,)),
        ))
        function = replace(
            demand.function,
            values=(returned, arithmetic, read_back),
            blocks=(CIRBlock(block, tuple(effects)),),
        )
        return LegacyTaintDemand(function, demand.port, demand.cfg,
                                 demand.demand.initial)

    def test_return_source_crosses_arithmetic_and_register_assignment(self):
        demand = self.build(overwrite=False)
        summary = demand.analyze()
        sink = next(item for item in summary.sinks if item.name == "system")
        self.assertTrue(any(dep.kind == "source" and dep.value == 0
                            for dep in sink.dependencies))

    def test_temporary_copy_and_constant_definition_match_old_replacement(self):
        base=self.build(overwrite=False)
        block=base.function.blocks[0]
        source_call, _, _, _, sink_call=block.effects
        returned=base.function.values[0]
        for label,input_value,expected_source in (
                ("source",returned,True),
                ("constant",Constant(0,ValueType.bv(32)),False)):
            with self.subTest(label=label):
                temporary=ValueRef("temporary-"+label,ValueType.bv(32))
                effects=(source_call,
                    Compute("o1",temporary,ValueOp.COPY,(input_value,)),
                    replace(sink_call,arguments=(temporary,)))
                function=replace(base.function,values=(returned,temporary),
                    blocks=(CIRBlock(block.id,effects),))
                demand=LegacyTaintDemand(function,base.port,base.cfg,
                                         base.demand.initial)
                sink=next(item for item in demand.analyze().sinks
                          if item.name=="system")
                actual=any(dep.kind=="source" and dep.value==0
                           for dep in sink.dependencies)
                self.assertEqual(actual,expected_source)

    def test_clean_register_redefinition_kills_prior_source(self):
        demand = self.build(overwrite=True)
        summary = demand.analyze()
        sink = next(item for item in summary.sinks if item.name == "system")
        self.assertFalse(any(dep.kind == "source" and dep.value == 0
                             for dep in sink.dependencies))

    def test_explicit_register_clobber_is_unknown_not_prior_source(self):
        demand = self.build(overwrite=False)
        block = demand.function.blocks[0]
        effects = list(block.effects)
        effects.insert(3, UnknownEffect("o1", "unsupported-register-effect",
            "unknown clobber", (), ("r4",), False))
        function = replace(demand.function,
                           blocks=(CIRBlock(block.id, tuple(effects)),))
        demand = LegacyTaintDemand(function, demand.port, demand.cfg,
                                   demand.demand.initial)
        sink = next(item for item in demand.analyze().sinks if item.name == "system")
        self.assertFalse(any(dep.kind == "source" and dep.value == 0
                             for dep in sink.dependencies))
        self.assertTrue(any(dep.kind == "unknown" for dep in sink.dependencies))

    def test_cast_round_trip_preserves_source_identity(self):
        demand = self.build(overwrite=False)
        block = demand.function.blocks[0]
        returned = demand.function.values[0]
        wide = ValueRef("wide", ValueType.bv(64))
        narrow = ValueRef("narrow", ValueType.bv(32))
        effects = list(block.effects)
        effects[1:1] = [
            Compute("o1", wide, ValueOp.ZERO_EXTEND, (returned,), (32,)),
            Compute("o1", narrow, ValueOp.EXTRACT, (wide,), (31, 0)),
        ]
        effects[3] = replace(effects[3], args=(narrow, Constant(0, ValueType.bv(32))))
        function = replace(demand.function,
                           values=demand.function.values + (wide, narrow),
                           blocks=(CIRBlock(block.id, tuple(effects)),))
        demand = LegacyTaintDemand(function, demand.port, demand.cfg,
                                   demand.demand.initial)
        sink = next(item for item in demand.analyze().sinks if item.name == "system")
        self.assertTrue(any(dep.kind == "source" and dep.value == 0
                            for dep in sink.dependencies))

    def test_source_return_survives_exact_stack_local_store_load(self):
        demand = self.build(overwrite=False)
        block = demand.function.blocks[0]
        source_call, _, _, _, sink_call = block.effects
        word = ValueType.bv(32)
        truth = Constant(True, ValueType.boolean())
        stack_cell = Constant(0x7fffffe0, ValueType.pointer(32))
        returned = demand.function.values[0]
        loaded = ValueRef("stack-local-loaded", word)
        effects = (
            source_call,
            StoreEffect("o1", stack_cell, returned, 32,
                        demand.port.engine.architecture.endian, truth),
            LoadEffect("o1", loaded, stack_cell, 32,
                       demand.port.engine.architecture.endian, truth),
            replace(sink_call, arguments=(loaded,)),
        )
        function = replace(demand.function,
                           values=(returned, loaded),
                           blocks=(CIRBlock(block.id, effects),))
        demand = LegacyTaintDemand(function, demand.port, demand.cfg,
                                   demand.demand.initial)
        sink = next(item for item in demand.analyze().sinks if item.name == "system")
        self.assertTrue(any(dep.kind == "source" and dep.value == 0
                            for dep in sink.dependencies))

    def test_branch_join_preserves_source_on_only_one_predecessor(self):
        demand = self.build(overwrite=False)
        entry = demand.function.blocks[0].id
        source_call, _, _, _, sink_call = demand.function.blocks[0].effects
        returned = demand.function.values[0]
        condition = ValueRef("branch-condition", ValueType.boolean())
        read_back = ValueRef("join-read", ValueType.bv(32))
        register = RegisterSlice("r4", 0, 32, 32)
        truth = Constant(True, ValueType.boolean())
        yes = BlockId(entry.function, 0x20)
        no = BlockId(entry.function, 0x40)
        join = BlockId(entry.function, 0x60)
        sink_point = ProgramPoint(join, 1, 0x64)
        demand.port.engine.origins += (replace(demand.port.engine.origins[1],
                                               id="o2", point=sink_point),)
        function = replace(demand.function,
            values=(returned, condition, read_back),
            blocks=(
                CIRBlock(entry, (source_call, BranchEffect("o0", condition, yes, no))),
                CIRBlock(yes, (WriteRegister("o1", register, returned,
                                           RegisterWritePolicy.FULL, truth),)),
                CIRBlock(no, (WriteRegister("o1", register,
                    Constant(0, ValueType.bv(32)), RegisterWritePolicy.FULL, truth),)),
                CIRBlock(join, (ReadRegister("o1", read_back, register),
                    replace(sink_call, origin="o2", site=CallSiteId(sink_point),
                            arguments=(read_back,)))),
            ))
        edges=frozenset((FlowEdge(entry,yes,FlowKind.TRUE),
                         FlowEdge(entry,no,FlowKind.FALSE),
                         FlowEdge(yes,join,FlowKind.FALL_THROUGH),
                         FlowEdge(no,join,FlowKind.FALL_THROUGH)))
        cfg=ControlFlowGraph(entry.function,frozenset((entry,yes,no,join)),edges,entry)
        demand=LegacyTaintDemand(function,demand.port,cfg,demand.demand.initial)
        sink=next(item for item in demand.analyze().sinks if item.name=="system")
        self.assertTrue(any(dep.kind=="source" and dep.value==0
                            for dep in sink.dependencies))

        half=ValueRef("branch-half",ValueType.bv(16))
        read_half=ValueRef("join-half",ValueType.bv(16))
        slice_16=RegisterSlice("r4",0,16,32)
        partial=replace(function,values=(returned,condition,half,read_half),blocks=(
            function.blocks[0],
            CIRBlock(yes,(Compute("o1",half,ValueOp.EXTRACT,(returned,),(15,0)),
                WriteRegister("o1",slice_16,half,
                              RegisterWritePolicy.PRESERVE_OTHERS,truth))),
            CIRBlock(no,(WriteRegister("o1",slice_16,
                Constant(0,ValueType.bv(16)),
                RegisterWritePolicy.PRESERVE_OTHERS,truth),)),
            CIRBlock(join,(ReadRegister("o1",read_half,slice_16),
                replace(function.blocks[3].effects[1],arguments=(read_half,)))),
        ))
        demand=LegacyTaintDemand(partial,demand.port,cfg,demand.demand.initial)
        sink=next(item for item in demand.analyze().sinks if item.name=="system")
        self.assertTrue(any(dep.kind=="source" and dep.value==0
                            for dep in sink.dependencies))

    def test_partial_register_write_propagates_only_the_written_slice(self):
        demand = self.build(overwrite=False)
        block = demand.function.blocks[0]
        source_call, _, _, _, sink_call = block.effects
        returned = demand.function.values[0]
        half = ValueRef("half", ValueType.bv(16))
        read_half = ValueRef("read-half", ValueType.bv(16))
        widened = ValueRef("widened", ValueType.bv(32))
        slice_16 = RegisterSlice("r4", 0, 16, 32)
        effects = (
            source_call,
            Compute("o1", half, ValueOp.EXTRACT, (returned,), (15, 0)),
            WriteRegister("o1", slice_16, half,
                          RegisterWritePolicy.PRESERVE_OTHERS,
                          Constant(True, ValueType.boolean())),
            ReadRegister("o1", read_half, slice_16),
            Compute("o1", widened, ValueOp.ZERO_EXTEND, (read_half,), (16,)),
            replace(sink_call, arguments=(widened,)),
        )
        function = replace(demand.function,
                           values=(returned, half, read_half, widened),
                           blocks=(CIRBlock(block.id, effects),))
        demand = LegacyTaintDemand(function, demand.port, demand.cfg,
                                   demand.demand.initial)
        sink = next(item for item in demand.analyze().sinks if item.name == "system")
        self.assertTrue(any(dep.kind == "source" and dep.value == 0
                            for dep in sink.dependencies))

    def test_partial_write_does_not_taint_the_unwritten_slice(self):
        demand = self.build(overwrite=False)
        block = demand.function.blocks[0]
        source_call, _, _, _, sink_call = block.effects
        returned = demand.function.values[0]
        half = ValueRef("half", ValueType.bv(16))
        read_upper = ValueRef("read-upper", ValueType.bv(16))
        widened = ValueRef("widened", ValueType.bv(32))
        effects = (
            source_call,
            Compute("o1", half, ValueOp.EXTRACT, (returned,), (15, 0)),
            WriteRegister("o1", RegisterSlice("r4", 0, 16, 32), half,
                          RegisterWritePolicy.PRESERVE_OTHERS,
                          Constant(True, ValueType.boolean())),
            ReadRegister("o1", read_upper, RegisterSlice("r4", 16, 16, 32)),
            Compute("o1", widened, ValueOp.ZERO_EXTEND, (read_upper,), (16,)),
            replace(sink_call, arguments=(widened,)),
        )
        function = replace(demand.function,
                           values=(returned, half, read_upper, widened),
                           blocks=(CIRBlock(block.id, effects),))
        demand = LegacyTaintDemand(function, demand.port, demand.cfg,
                                   demand.demand.initial)
        sink = next(item for item in demand.analyze().sinks if item.name == "system")
        self.assertFalse(any(dep.kind == "source" and dep.value == 0
                             for dep in sink.dependencies))
        self.assertTrue(any(dep.kind == "unknown" for dep in sink.dependencies))

    def test_conditional_partial_write_retains_source_and_prior_unknown(self):
        demand = self.build(overwrite=False)
        block = demand.function.blocks[0]
        source_call, _, _, _, sink_call = block.effects
        returned = demand.function.values[0]
        condition = ValueRef("conditional-write", ValueType.boolean())
        half = ValueRef("conditional-half", ValueType.bv(16))
        read_half = ValueRef("conditional-read", ValueType.bv(16))
        widened = ValueRef("conditional-wide", ValueType.bv(32))
        slice_16 = RegisterSlice("r4", 0, 16, 32)
        effects = (
            source_call,
            Compute("o1", half, ValueOp.EXTRACT, (returned,), (15, 0)),
            WriteRegister("o1", slice_16, half,
                          RegisterWritePolicy.PRESERVE_OTHERS, condition),
            ReadRegister("o1", read_half, slice_16),
            Compute("o1", widened, ValueOp.ZERO_EXTEND, (read_half,), (16,)),
            replace(sink_call, arguments=(widened,)),
        )
        function = replace(demand.function,
                           values=(returned, condition, half, read_half, widened),
                           blocks=(CIRBlock(block.id, effects),))
        demand = LegacyTaintDemand(function, demand.port, demand.cfg,
                                   demand.demand.initial)
        sink = next(item for item in demand.analyze().sinks if item.name == "system")
        self.assertTrue(any(dep.kind == "source" and dep.value == 0
                            for dep in sink.dependencies))
        self.assertTrue(any(dep.kind == "unknown" for dep in sink.dependencies))

    def test_conditional_clean_slice_keeps_prior_source_alternative(self):
        demand = self.build(overwrite=False)
        block = demand.function.blocks[0]
        source_call, _, _, _, sink_call = block.effects
        returned = demand.function.values[0]
        condition = ValueRef("clean-write-condition", ValueType.boolean())
        half = ValueRef("prior-source-half", ValueType.bv(16))
        read_half = ValueRef("read-after-clean", ValueType.bv(16))
        widened = ValueRef("wide-after-clean", ValueType.bv(32))
        slice_16 = RegisterSlice("r4", 0, 16, 32)
        effects = (
            source_call,
            Compute("o1", half, ValueOp.EXTRACT, (returned,), (15, 0)),
            WriteRegister("o1", slice_16, half,
                          RegisterWritePolicy.PRESERVE_OTHERS,
                          Constant(True, ValueType.boolean())),
            WriteRegister("o1", slice_16,
                          Constant(0, ValueType.bv(16)),
                          RegisterWritePolicy.PRESERVE_OTHERS, condition),
            ReadRegister("o1", read_half, slice_16),
            Compute("o1", widened, ValueOp.ZERO_EXTEND, (read_half,), (16,)),
            replace(sink_call, arguments=(widened,)),
        )
        function = replace(demand.function,
                           values=(returned, condition, half, read_half, widened),
                           blocks=(CIRBlock(block.id, effects),))
        demand = LegacyTaintDemand(function, demand.port, demand.cfg,
                                   demand.demand.initial)
        sink = next(item for item in demand.analyze().sinks if item.name == "system")
        self.assertTrue(any(dep.kind == "source" and dep.value == 0
                            for dep in sink.dependencies))


if __name__ == "__main__":
    unittest.main()
