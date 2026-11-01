import unittest
from dataclasses import replace
import test_p7_demand as fixtures
from emtaint.core.contracts import ValueRef,ValueType,Constant
from emtaint.ir.canonical import CIRBlock,LoadEffect
from emtaint.analysis.taint.demand import LegacyTaintDemand


class RuntimeLengthTests(unittest.TestCase):
    def test_mutable_global_loader_zero_is_not_a_proven_zero_length_source(self):
        d,bid=fixtures.TaintDemandTests().make((('recv',(0,0x1000,0,0),True),('system',(0x1000,),True)))
        count=ValueRef('runtime-source-count',ValueType.bv(32));effects=d.function.blocks[0].effects
        load=LoadEffect('o0',count,Constant(0x2000,ValueType.pointer(32)),32,d.port.engine.architecture.endian,Constant(True,ValueType.boolean()))
        source=replace(effects[0],arguments=effects[0].arguments[:2]+(count,)+effects[0].arguments[3:])
        function=replace(d.function,values=(count,),blocks=(CIRBlock(bid,(load,source,effects[1])),))
        d=LegacyTaintDemand(function,d.port,d.cfg,d.demand.initial);result=d.analyze()
        self.assertTrue(any(dep.kind=='source' for sink in result.sinks for dep in sink.dependencies))

    def test_mutable_format_and_missing_terminator_remain_unknown(self):
        d,_=fixtures.TaintDemandTests().make((('recv',(0,0x2000,16,0),True),('_system',(0x1000,0x2000),True)),format_data=b'echo %s\0')
        d.port.engine.segments=tuple((a,b,c,6) for a,b,c,_ in d.port.engine.segments)
        result=d.analyze()
        self.assertTrue(any(dep.kind=='source' for sink in result.sinks for dep in sink.dependencies))
        self.assertTrue(any(dep.kind=='unknown' for sink in result.sinks for dep in sink.dependencies))
        self.assertTrue(any('Unknown format' in str(note) for note in result.pending))
