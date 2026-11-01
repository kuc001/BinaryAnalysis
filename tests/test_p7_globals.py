import unittest
import test_p7_demand as fixtures


class GlobalDemandTests(unittest.TestCase):
    def test_immutable_literal_is_not_exported_as_caller_mutable_storage(self):
        d,_=fixtures.TaintDemandTests().make((('system',(0x1000,),True),))
        d.port.engine.segments=tuple((a,b,c,4) for a,b,c,_ in d.port.engine.segments)
        result=d.analyze()
        self.assertFalse(any(dep.kind=='global' for sink in result.sinks for dep in sink.dependencies))

    def test_writable_global_requirement_still_binds_at_the_caller(self):
        d,_=fixtures.TaintDemandTests().make((('system',(0x1000,),True),))
        result=d.analyze()
        self.assertTrue(any(dep.kind=='global' and dep.value==0x1000 for sink in result.sinks for dep in sink.dependencies))
