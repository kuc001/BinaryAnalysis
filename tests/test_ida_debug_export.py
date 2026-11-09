"""D4 BinaryId/RVA address mapping and debug-sidecar tests."""

import json
from pathlib import Path
import uuid
import unittest

import test_debug_provenance as d1

from emtaint.analysis_debugging import (
    DEBUG_SIDECAR_VERSION,
    IdaAddressIndex,
    ida_effective_address,
)
from emtaint.core import BinaryId


class IdaDebugExportTests(unittest.TestCase):
    def test_binary_rva_and_ida_ea_queries_are_bidirectional(self):
        result = d1.lower(())
        binary = BinaryId(result.module.binary_sha256)
        index = IdaAddressIndex(result.provenance, 0x400000)
        by_rva = index.by_rva(binary, 0x1000)
        self.assertTrue(by_rva)
        self.assertEqual(by_rva, index.by_ida_ea(binary, 0x401000))
        self.assertEqual(
            ida_effective_address(0x400000, 0x1000), 0x401000
        )
        self.assertEqual(index.by_ida_ea(binary, 0x3FFFFF), ())

    def test_export_is_independent_rebuildable_sidecar(self):
        result = d1.lower((
            d1.pyvex.stmt.WrTmp(0, d1.pyvex.expr.Get(8, "Ity_I32")),
        ), ("Ity_I32",))
        before_schema = result.module.schema_version
        index = result.debug.ida_index(0x400000)
        destination = Path(".debug") / (
            "test-ida-map-" + uuid.uuid4().hex + ".json"
        )
        try:
            index.export(destination)
            payload = json.loads(destination.read_text(encoding="utf8"))
        finally:
            destination.unlink(missing_ok=True)
        self.assertEqual(payload["schema_version"], DEBUG_SIDECAR_VERSION)
        self.assertEqual(
            payload["compatibility"]["storage"],
            "independent-additive-sidecar",
        )
        self.assertEqual(result.module.schema_version, before_schema)
        self.assertIn("0x401000", payload["ida_ea_to_origin_ids"])
        self.assertTrue(any(record["value_ids"] for record in payload["records"]))
        self.assertTrue(any(
            record["registers"] for record in payload["records"]
        ))

    def test_binary_identity_prevents_cross_image_lookup(self):
        result = d1.lower(())
        index = IdaAddressIndex(result.provenance, 0)
        foreign = BinaryId("0" * 64)
        self.assertEqual(index.by_rva(foreign, 0x1000), ())


if __name__ == "__main__":
    unittest.main()
