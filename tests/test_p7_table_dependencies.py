import unittest

from emtaint.analysis.taint.table_dependencies import TableReadIndex
from emtaint.analysis.taint.tables import TableRoot


class TableReadIndexTests(unittest.TestCase):
    def test_changed_root_invalidates_only_exact_and_broad_readers(self):
        first=TableRoot('binary','global',0x1000)
        second=TableRoot('binary','global',0x2000)
        missing=TableRoot('binary','global',0x3000)
        index=TableReadIndex()
        index.replace('first',(first,),())
        index.replace('second',(second,),())
        index.replace('fallback',(missing,),(missing,))
        self.assertEqual(index.affected(first),frozenset(('first','fallback')))
        self.assertEqual(index.affected(second),frozenset(('second','fallback')))
        index.replace('fallback',(second,),())
        self.assertEqual(index.affected(first),frozenset(('first',)))
        self.assertEqual(index.affected(second),frozenset(('second','fallback')))

    def test_invalid_broad_read_does_not_discard_previous_dependencies(self):
        first=TableRoot('binary','global',0x1000)
        second=TableRoot('binary','global',0x2000)
        index=TableReadIndex();index.replace('reader',(first,),())
        with self.assertRaises(ValueError):index.replace('reader',(second,),(first,))
        self.assertEqual(index.affected(first),frozenset(('reader',)))
        self.assertFalse(index.affected(second))
