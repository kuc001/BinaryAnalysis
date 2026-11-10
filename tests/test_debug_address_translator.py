"""Tests for explicit IDA and runtime address projections."""
import unittest
from emtaint.analysis_debugging import AddressTranslator
from emtaint.core import BinaryId

class AddressTranslatorTests(unittest.TestCase):
    def setUp(self):
        self.binary = BinaryId("1" * 64)

    def test_user_base(self):
        translator = AddressTranslator(self.binary, ida_image_base=0x140000000)
        self.assertEqual(translator.to_ida_va(self.binary, 0x15688), 0x140015688)
        self.assertEqual(translator.format_address(self.binary, 0x15688, "Instruction"),
                         "Instruction: IDA VA 0x140015688 (RVA 0x15688)")

    def test_second_base(self):
        translator = AddressTranslator(self.binary, ida_image_base=0x180000000)
        self.assertEqual(translator.to_ida_va(self.binary, 0x15688), 0x180015688)

    def test_missing_base(self):
        view = AddressTranslator(self.binary).view(self.binary, 0x15688)
        self.assertIsNone(view.ida_va)
        self.assertEqual(view.reason, "IDA_IMAGE_BASE_NOT_CONFIGURED")

    def test_runtime_independent(self):
        translator = AddressTranslator(self.binary, ida_image_base=0x140000000,
                                       runtime_base=0x7FF700000000)
        view = translator.view(self.binary, 0x15688)
        self.assertEqual(view.ida_va, 0x140015688)
        self.assertEqual(view.runtime_va, 0x7FF700015688)

    def test_reverse_and_binary_scope(self):
        translator = AddressTranslator(self.binary, ida_image_base=0x140000000)
        self.assertEqual(translator.to_rva(self.binary, 0x140015688), 0x15688)
        self.assertIsNone(translator.to_rva(self.binary, 0x13FFFFFFF))
        with self.assertRaises(ValueError):
            translator.to_ida_va(BinaryId("2" * 64), 0x15688)

    def test_overflow(self):
        translator = AddressTranslator(self.binary, ida_image_base=(1 << 64) - 8)
        view = translator.view(self.binary, 0x15688)
        self.assertIsNone(view.ida_va)
        self.assertEqual(view.reason, "IDA_ADDRESS_OVERFLOW")

if __name__ == "__main__":
    unittest.main()
