import unittest
from emtaint.analysis.taint.guards import legacy_constraint
from emtaint.procedures.legacy import lookup


class LegacyGuardTests(unittest.TestCase):
    def test_all_active_old_constraint_procedures_have_exact_rules(self):
        for name,operation,kind,source in (
            ('atoi','integer_return',4,0),('atol','integer_return',4,0),
            ('atoll','integer_return',4,0),('strtol','integer_return',4,0),
            ('strtoll','integer_return',4,0),('strtoul','integer_return',4,0),
            ('strlen','integer_return',5,0),
            ('strcmp','constraint',2,0),('strcasecmp','constraint',2,0),
            ('stricmp','constraint',2,0),
            ('inet_pton','constraint',1,1),('inet_aton','constraint',1,0),
            ('gethostbyname','constraint',1,0),('gethostbyname2','constraint',1,0),
        ):
            with self.subTest(name=name):
                rule=lookup(name)
                self.assertIsNotNone(rule)
                self.assertEqual((rule.operation,rule.constraint_type,rule.source),
                    (operation,kind,source))

    def test_strlen_and_integer_bounds_exclude_sentinel(self):
        for kind in (4,5):
            self.assertEqual(legacy_constraint(kind,'lt',32).constraints,(32,))
            self.assertEqual(legacy_constraint(kind,'ge',32).constraints,())
            self.assertEqual(legacy_constraint(kind,'eq',0xffffffff).constraints,())

    def test_old_sanitizer_direction_does_not_prove_feasibility(self):
        self.assertTrue(legacy_constraint(2,'eq',0).kill)
        self.assertFalse(legacy_constraint(2,'ne',0).kill)
        self.assertTrue(legacy_constraint(1,'ne',0).kill)
        self.assertFalse(legacy_constraint(1,'eq',0).kill)
        self.assertFalse(legacy_constraint(6,'eq',0,pointer=True).kill)
        self.assertTrue(legacy_constraint(6,'eq',0,pointer=False).kill)
        self.assertEqual(legacy_constraint(2,'eq',0).classification,'legacy-constraint-heuristic')

    def test_filter_kill_requires_exact_old_type_direction_and_value(self):
        for kind,operation,bound,options,expected in (
            (0,'eq',0,{'symbol':True},True),
            (0,'eq',0,{'symbol':False},False),
            (0,'ne',0,{'symbol':True},False),
            (1,'lt',0,{},True),
            (1,'eq',0,{},False),
            (2,'eq',1,{},False),
            (6,'eq',0,{'pointer':False},True),
            (6,'eq',0,{'pointer':True},False),
            (7,'eq',0,{},False),
        ):
            with self.subTest(kind=kind,operation=operation,bound=bound,options=options):
                decision=legacy_constraint(kind,operation,bound,**options)
                self.assertIs(decision.kill,expected)
                self.assertEqual(decision.constraints,())
