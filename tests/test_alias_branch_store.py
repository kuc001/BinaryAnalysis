"""Regression for a callee write through a branch-selected pointer."""

from pathlib import Path
import unittest

from emtaint.analysis.aliasing.program import NativeAliasProgram


ROOT = Path(__file__).resolve().parents[2]
BINARY = ROOT / "Test-Suite-master" / "Binaries" / "cs_tests" / "cs10.c.elf"
WRAPPER_BINARY = ROOT / "Test-Suite-master" / "Binaries" / "cs_tests" / "cs15.c.elf"
VIRTUAL_BINARY = ROOT / "Test-Suite-master" / "Binaries" / "basic_cpp_tests" / "abstract.cpp.elf"
CONSTRUCTOR_BINARY = ROOT / "Test-Suite-master" / "Binaries" / "basic_cpp_tests" / "constructor-1.cpp.elf"
INDEXED_BINARY = ROOT / "Test-Suite-master" / "Binaries" / "basic_c_tests" / "field-ptr-arith-varIdx.c.elf"


@unittest.skipUnless(BINARY.is_file(), "Branch-store ELF is unavailable")
class ConditionalCalleeStoreTests(unittest.TestCase):
    def test_one_must_target_cannot_kill_other_target_path(self):
        program = NativeAliasProgram(BINARY, ("MAYALIAS",))
        observations = program.query_calls()
        self.assertEqual(len(observations), 2)
        self.assertEqual([item[3] for item in observations], ["MAYALIAS", "MAYALIAS"])
        self.assertTrue(all(item[6] for item in observations))


@unittest.skipUnless(WRAPPER_BINARY.is_file(), "Wrapper-store ELF is unavailable")
class TransitiveCalleeStoreTests(unittest.TestCase):
    @unittest.expectedFailure  # Nested Store/Read order needs versioned summaries.
    def test_wrapper_exports_nested_store_effects(self):
        program = NativeAliasProgram(WRAPPER_BINARY, ("MUSTALIAS",))
        observations = program.query_calls()
        self.assertEqual(len(observations), 2)
        self.assertEqual([item[3] for item in observations], ["MUSTALIAS"] * 2)
        self.assertTrue(all(item[6] for item in observations))


@unittest.skipUnless(VIRTUAL_BINARY.is_file(), "C++ virtual-call ELF is unavailable")
class VirtualConstructorStoreTests(unittest.TestCase):
    def test_final_vptr_store_resolves_virtual_caller_context(self):
        program = NativeAliasProgram(VIRTUAL_BINARY, ("NOALIAS", "MUSTALIAS"))
        observations = program.query_calls()
        self.assertEqual(len(observations), 6)
        self.assertEqual(
            [item[3] for item in observations[2:]],
            ["MUSTALIAS", "NOALIAS", "NOALIAS", "MUSTALIAS"],
        )
        self.assertTrue(all(item[6] for item in observations[2:]))


@unittest.skipUnless(CONSTRUCTOR_BINARY.is_file(), "C++ constructor ELF is unavailable")
class TransitiveCallerContextTests(unittest.TestCase):
    def test_constructor_formal_reaches_main_actual(self):
        program = NativeAliasProgram(CONSTRUCTOR_BINARY, ("MUSTALIAS",))
        observations = program.query_calls()
        self.assertEqual(len(observations), 2)
        self.assertEqual([item[3] for item in observations], ["MUSTALIAS"] * 2)
        self.assertTrue(all(item[6] for item in observations))


@unittest.skipUnless(INDEXED_BINARY.is_file(), "Indexed-stack ELF is unavailable")
class IndexedStackAddressTests(unittest.TestCase):
    def test_unknown_index_cannot_prove_no_alias_from_residue(self):
        program = NativeAliasProgram(INDEXED_BINARY, ("MAYALIAS",))
        observations = program.query_calls()
        self.assertEqual(len(observations), 1)
        self.assertNotEqual(observations[0][3], "NOALIAS")
        self.assertFalse(observations[0][6])
        self.assertIn("ADDRESS_UNRESOLVED", observations[0][7])


if __name__ == "__main__":
    unittest.main()
