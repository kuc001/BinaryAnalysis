"""Regression tests for legacy graph-node contracts."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_original_tempdir = tempfile.tempdir
tempfile.tempdir = str(ROOT / '.p7-work')
try:
    from emtaint.analysis.graph.node.stmt_node import StmtNode
finally:
    tempfile.tempdir = _original_tempdir


class StatementNodeTests(unittest.TestCase):
    """Verify statement extents at the public graph-node boundary."""

    def test_statement_count_must_match_declared_size(self) -> None:
        """Invalid external extents raise explicitly instead of using assert."""

        with self.assertRaises(ValueError):
            StmtNode(0x1000, 1, [])

    def test_empty_boundary_node_is_explicit(self) -> None:
        """A zero-size boundary is represented by ``None`` statements."""

        node = StmtNode(0x1000, 0, None)
        self.assertEqual((node.addr, node.size, node.stmts), (0x1000, 0, None))


if __name__ == '__main__':
    unittest.main()
