"""CFGFast shared-suffix normalization regressions."""

from pathlib import Path
import unittest

from emtaint.frontends.angr_vex import AngrVexFrontend
from emtaint.frontends.inputs import InputBlock, InputError
from emtaint.frontends.vex_input import _partition_discovered_blocks
from emtaint.graph import FlowKind
from emtaint.ir.canonical import UnknownEffect


WORKSPACE = Path(__file__).resolve().parents[2]
ARRAY_ALIAS_4 = (
    WORKSPACE
    / "Test-Suite-master"
    / "Binaries"
    / "fs_tests"
    / "array_alias_4.c.elf"
)


class DiscoveredBlockPartitionTests(unittest.TestCase):
    def test_shared_suffix_becomes_one_non_overlapping_partition(self):
        blocks = (
            InputBlock(0x400991, 0x4009AC),
            InputBlock(0x400999, 0x4009AC),
        )
        self.assertEqual(
            _partition_discovered_blocks(blocks),
            (
                InputBlock(0x400991, 0x400999),
                InputBlock(0x400999, 0x4009AC),
            ),
        )

    def test_conflicting_decode_modes_are_not_silently_merged(self):
        blocks = (
            InputBlock(0x1000, 0x1010, "default"),
            InputBlock(0x1008, 0x1010, "thumb"),
        )
        with self.assertRaisesRegex(InputError, "conflicting decode modes"):
            _partition_discovered_blocks(blocks)


@unittest.skipUnless(ARRAY_ALIAS_4.is_file(), "array_alias_4 ELF unavailable")
class NativeSharedSuffixTests(unittest.TestCase):
    def test_array_alias_4_preserves_both_paths_to_shared_suffix(self):
        frontend = AngrVexFrontend(ARRAY_ALIAS_4)
        main = frontend.project.loader.find_symbol("main").rebased_addr
        specification = frontend.discover((main,))[0]
        ranges = tuple((block.start, block.end) for block in specification.blocks)
        self.assertIn((0x400991, 0x400999), ranges)
        self.assertIn((0x400999, 0x4009AC), ranges)
        self.assertFalse(any(
            left[1] > right[0]
            for left, right in zip(ranges, ranges[1:])
        ))

        result = frontend.lift((specification,))
        cfg = result.cfgs()[0]
        base = frontend.image.image_base
        edges = {
            (edge.source.rva + base, edge.target.rva + base, edge.kind)
            for edge in cfg.edges
        }
        self.assertIn((0x400991, 0x400999, FlowKind.UNKNOWN), edges)
        branch_targets = {
            target
            for source, target, _kind in edges
            if source == 0x400963
        }
        self.assertEqual(branch_targets, {0x400991, 0x400999})

        entry = next(
            block for block in result.module.functions[0].blocks
            if block.id.rva + base == 0x400963
        )
        unknown_control = [
            effect for effect in entry.effects
            if isinstance(effect, UnknownEffect)
            and effect.source_opcode == "UndefinedTmp"
            and effect.may_change_control
        ]
        self.assertTrue(unknown_control)
        self.assertTrue(all(
            not effect.may_write_regions and not effect.may_write_registers
            for effect in unknown_control
        ))


if __name__ == "__main__":
    unittest.main()
