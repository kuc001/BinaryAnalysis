import unittest
from emtaint.procedures.legacy import legacy_copy_weak_kind,legacy_copy_length_constraints


class BoundedCopyPolicyTests(unittest.TestCase):
    def test_native_old_marking_truth_table_and_unknown_are_distinct(self):
        cases=((False,True,False,'copy'),(True,True,False,None),
            (True,True,True,'copy_length'),(True,False,True,None),
            (True,True,None,'unknown'),(False,None,False,'unknown'))
        for bounded,source,length,expected in cases:
            with self.subTest(bounded=bounded,source=source,length=length):
                self.assertEqual(legacy_copy_weak_kind(bounded=bounded,buffer_tainted=source,length_tainted=length),expected)

    def test_only_old_atoi_cons_type_contributes_numeric_length_constraint(self):
        self.assertEqual(legacy_copy_length_constraints(((4,(99,0,100)),(5,(16,)),(0,(32,)),(4,('S',)),(4,(1,)))),(99,1))
