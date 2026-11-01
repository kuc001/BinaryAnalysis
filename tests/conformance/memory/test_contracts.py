"""Twelve P3 contract fixtures. None is reported as a P5 Gate M runtime pass."""
import unittest
from .fixtures import CASES, exercise


class MemoryContractFixtures(unittest.TestCase):
    pass


def contract_test(case):
    def test(self):
        result = exercise(case)
        self.assertEqual(result['contract_status'], 'PASS')
        self.assertEqual(result['runtime_gate_m'], 'NOT_IMPLEMENTED')
    return test


for case in CASES:
    setattr(MemoryContractFixtures, 'test_' + case.replace('-', '_'), contract_test(case))
