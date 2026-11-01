"""Runtime counterparts of the preserved P3 descriptor-only conformance suite."""
import unittest
from .runtime_fixtures import CASES,exercise


class MemoryRuntimeConformance(unittest.TestCase):
    pass


for case in CASES:
    def test(self,case=case):
        self.assertEqual(exercise(case)['runtime_gate_m'],'PASS')
    setattr(MemoryRuntimeConformance,'test_'+case.replace('-','_'),test)
