"""P4 input validation without angr, IDA, or third-party libraries."""
from pathlib import Path
import struct
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from emtaint.frontends.inputs import InputBlock, FunctionInput, parse_ida_cfg, ELFImage, InputError
from emtaint.frontends.saved_cir import load_saved_cir


def tiny_elf(code=b'\x90\xc3', machine=62):
    data = bytearray(0x100 + len(code))
    data[:16] = b'\x7fELF\x02\x01\x01' + b'\0' * 9
    struct.pack_into('<HHIQQQIHHHHHH', data, 16, 2, machine, 1, 0x400100, 64, 0, 0,
                     64, 56, 1, 0, 0, 0)
    struct.pack_into('<IIQQQQQQ', data, 64, 1, 5, 0, 0x400000, 0, len(data), len(data), 0x1000)
    data[0x100:] = code
    return bytes(data)


class InputTests(unittest.TestCase):
    def test_real_ida_shape_preserves_blocks_edges_and_calls(self):
        doc = {'400100': {'block': [[0x400100, 0x400104], [0x400104, 0x400108]],
               'jmp': [[0x400100, 0x400104]], 'call': [[0x400100, 0x400102, 'callee']]}}
        specs = parse_ida_cfg(doc)
        self.assertEqual(len(specs[0].blocks), 2)
        self.assertEqual(specs[0].calls[0].target, 'callee')
        self.assertEqual(specs[0].edges, ((0x400100, 0x400104),))

    def test_malformed_metadata_is_rejected_without_skipping(self):
        for doc in ({'bad-key!': {}}, {'10': {'block': [[16, 15]], 'jmp': [], 'call': []}},
                    {'10': {'block': [[16, 20]], 'jmp': [[16, 99]], 'call': []}},
                    {'10': {'block': [[True, 20]], 'jmp': [], 'call': []}}):
            with self.subTest(doc=doc), self.assertRaises(InputError):
                parse_ida_cfg(doc)

    def test_zero_length_ida_boundary_is_preserved_explicitly(self):
        doc = {'10': {'block': [[16, 20], [24, 24]], 'jmp': [[16, 24]], 'call': [], 'name': 'caller'}}
        spec = parse_ida_cfg(doc)[0]
        self.assertTrue(spec.blocks[1].boundary)
        self.assertEqual(spec.edges, ((16, 24),))
        self.assertEqual(spec.name, 'caller')

    def test_elf_mapping_uses_virtual_addresses_and_checks_bounds(self):
        image = ELFImage(tiny_elf())
        self.assertEqual(image.read(0x400100, 2), b'\x90\xc3')
        self.assertEqual(image.image_base, 0x400000)
        self.assertEqual(image.machine, 62)
        with self.assertRaises(InputError):
            image.read(0x500000, 4)
        with self.assertRaises(InputError):
            ELFImage(b'not-ELF')

    def test_function_bounds_and_mode_are_explicit(self):
        for args in ((1, 0), (-1, 2), (True, 4)):
            with self.subTest(args=args), self.assertRaises(InputError):
                InputBlock(*args)
        with self.assertRaises(InputError):
            InputBlock(0, 4, 'guessed-mode')
        self.assertEqual(FunctionInput(0, 'zero', (InputBlock(0, 4),)).address, 0)

    def test_no_mutable_call_tables_or_unknown_metadata_fields(self):
        with self.assertRaises(InputError):
            FunctionInput(0, 'zero', (InputBlock(0, 4),), calls=[])
        with self.assertRaises(InputError):
            parse_ida_cfg({'0': {'block': [[0, 4]], 'jmp': [], 'call': [], 'unknown_effect': 1}})

    def test_saved_cir_requires_a_positive_byte_budget(self):
        for budget in (0, -1, True, 1.5):
            with self.subTest(budget=budget), self.assertRaises(InputError):
                load_saved_cir(ROOT, max_bytes=budget)


if __name__ == '__main__':
    unittest.main()
