"""D1 provenance sidecar and frontend capture tests."""

import hashlib
import os
from pathlib import Path
import tempfile
import unittest

_CACHE = Path(__file__).resolve().parents[1] / ".debug"
_CACHE.mkdir(exist_ok=True)
for _name in ("TEMP", "TMP", "TMPDIR"):
    os.environ[_name] = str(_CACHE)
tempfile.tempdir = str(_CACHE)

import archinfo
import pyvex

from emtaint.frontends.inputs import FunctionInput, InputBlock
from emtaint.frontends.vex_lowering import NativeChunk, VEXLowerer


def lower(statements, types=()):
    """Lower a small VEX block through the production frontend boundary."""

    architecture = archinfo.ArchX86()
    start = 0x1000
    vex = pyvex.IRSB.empty_block(
        architecture,
        start,
        statements=[pyvex.stmt.IMark(start, 4, 0), *statements],
        nxt=pyvex.expr.Const(pyvex.const.U32(start + 4)),
        tyenv=pyvex.IRTypeEnv(architecture, list(types)),
        jumpkind="Ijk_Boring",
        size=4,
    )
    specification = FunctionInput(
        start, "fixture", (InputBlock(start, start + 4),)
    )
    chunk = NativeChunk(
        specification,
        start,
        start + 4,
        start,
        start + 4,
        "default",
        vex,
        hashlib.sha256(b"code").hexdigest(),
    )
    lowerer = VEXLowerer(
        hashlib.sha256(b"debug-provenance").hexdigest(),
        0,
        architecture,
        "test",
    )
    return lowerer.lower((specification,), (chunk,))


class ProvenanceIndexTests(unittest.TestCase):
    def test_frontend_records_temporary_register_and_reverse_instruction(self):
        result = lower(
            (pyvex.stmt.WrTmp(0, pyvex.expr.Get(8, "Ity_I32")),),
            ("Ity_I32",),
        )
        temporary = next(
            value
            for value in result.module.functions[0].values
            if ":t" in value.id
        )
        origins = result.provenance.origins(temporary)
        self.assertTrue(any(item.vex_temporary == 0 for item in origins))
        self.assertTrue(
            any(
                item.register_offset == 8 and item.register_name == "eax"
                for value in result.module.functions[0].values
                for item in result.provenance.origins(value)
            )
        )
        reverse = result.provenance.values_for_instruction(
            result.module.binary_sha256, 0x1000
        )
        self.assertIn(temporary, reverse)

    def test_guarded_load_value_preserves_multiple_cir_definitions(self):
        statement = pyvex.stmt.LoadG(
            "Iend_LE",
            "ILGop_Ident32",
            0,
            pyvex.expr.Const(pyvex.const.U32(0x2000)),
            pyvex.expr.Const(pyvex.const.U32(7)),
            pyvex.expr.Const(pyvex.const.U1(1)),
        )
        result = lower((statement,), ("Ity_I32",))
        multi_defined = [
            value
            for value in result.module.functions[0].values
            if len(result.provenance.definitions(value)) > 1
        ]
        self.assertEqual(len(multi_defined), 1)
        self.assertEqual(
            {item.effect_kind for item in result.provenance.definitions(multi_defined[0])},
            {"Compute", "LoadEffect"},
        )

    def test_unknown_value_is_explicitly_absent(self):
        result = lower(())
        self.assertIsNone(result.provenance.value("f1000:v999"))
        self.assertEqual(result.provenance.origins("f1000:v999"), ())


if __name__ == "__main__":
    unittest.main()
