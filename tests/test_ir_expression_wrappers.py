"""Regression tests for typed legacy VEX expression adapters."""

from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# pyvex creates its FFI parser cache on first import. Keep that native side
# effect inside the repository's ignored test workspace under the sandbox.
_original_tempdir = tempfile.tempdir
tempfile.tempdir = str(ROOT / '.p7-work')
try:
    from emtaint.ir.expressions.binder import Binder
    from emtaint.ir.expressions.const import Const
    from emtaint.ir.expressions.rd_tmp import RdTmp
    from pyvex.const import U32
finally:
    tempfile.tempdir = _original_tempdir


class ExpressionWrapperTests(unittest.TestCase):
    """Verify wrapper construction and stable legacy operand identities."""

    def test_binder_delegates_to_the_native_constructor(self) -> None:
        """The adapter must initialize, not call attributes on ``super`` itself."""

        self.assertEqual(Binder(7).binder, 7)

    def test_constant_and_temporary_names_preserve_native_values(self) -> None:
        """Legacy names retain the exact constant and temporary identifiers."""

        self.assertEqual(Const(U32(0xFFFFFFFF)).get_name(), 0xFFFFFFFF)
        self.assertEqual(RdTmp(12).get_name(), 't12')


if __name__ == '__main__':
    unittest.main()
