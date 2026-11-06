"""Manual binary locators agree with observed call arguments."""

from pathlib import Path
import unittest

from emtaint.analysis.aliasing.program import NativeAliasProgram


ROOT = Path(__file__).resolve().parents[2] / "Test-Suite-master" / "Binaries"
STRONG = ROOT / "fs_tests" / "strong_update.c.elf"
GLOBAL = ROOT / "basic_c_tests" / "CI-global.c.elf"


@unittest.skipUnless(STRONG.is_file(), "Strong-update ELF is unavailable")
class RegisterLocatorTests(unittest.TestCase):
    def test_call_registers_agree_with_binary_observer_arguments(self):
        program = NativeAliasProgram(STRONG, ("NOALIAS",))
        observation, = (
            item for item in program.query_calls() if item[2] == "NOALIAS"
        )
        manual = program.query_call_locators(
            "main", observation[1], "reg:rdi", "reg:rsi",
        )
        self.assertEqual(manual[0], observation[3])
        self.assertEqual(manual[0], "NOALIAS")
        self.assertTrue(manual[3])


@unittest.skipUnless(GLOBAL.is_file(), "CI-global ELF is unavailable")
class MemoryLocatorTests(unittest.TestCase):
    def test_global_pointer_slot_and_pointee_address_agree_with_observer(self):
        program = NativeAliasProgram(GLOBAL, ("MAYALIAS",))
        observation, = program.query_calls()
        pointer_slot = program._symbol_address("p_global")
        pointee = program._symbol_address("global")
        memory = program.query_call_locators(
            "main", observation[1], "arg:0", "mem:" + hex(pointer_slot),
        )
        address = program.query_call_locators(
            "main", observation[1], "arg:0", "addr:" + hex(pointee),
        )
        self.assertEqual(memory[0], observation[3])
        self.assertEqual(address[0], observation[3])
        self.assertEqual(memory[0], "MUSTALIAS")
        self.assertTrue(memory[3] and address[3])


if __name__ == "__main__":
    unittest.main()
