"""Run the existing F0 assertions on saved records without restarting native acquisition."""
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from fixture_config import ROOT, require_file

from emtaint.artifacts import AcquisitionRef, load, publish
from emtaint.core import BinaryId, FunctionId

sys.path.insert(0, str(ROOT / "tests/f0"))
try:
    import test_acquisition as f0
finally:
    sys.path.pop(0)

SAVED = ROOT / ".f0-runtime/artifacts/generation-a7470d49744a41d99fc673785fb76f73"
MANIFEST_PIN = "6dce3efbdf607764bb9a9ffb8652d9204f9508a0952327e97525a2c64be7147c"


def prepare_binary(test_class: type[unittest.TestCase]) -> None:
    binary = Path(os.environ.get("F1_BINARY", os.environ.get("F0_BINARY", f0.DEFAULT_BINARY)))
    require_file(binary, "F1_BINARY")
    test_class.enterClassContext(patch.dict(os.environ, {"F0_BINARY": str(binary)}))


class SavedF0ProjectRegression(f0.ProjectInputTests):
    @classmethod
    def setUpClass(cls) -> None:
        prepare_binary(cls)
        super().setUpClass()


class SavedF0Regression(f0.RealAcquisitionTests):
    @classmethod
    def setUpClass(cls) -> None:
        generation = Path(os.environ.get("F0_SAVED_GENERATION", SAVED))
        pin = os.environ.get("F0_MANIFEST_SHA256")
        if "F0_SAVED_GENERATION" in os.environ and not pin:
            raise ValueError("F0_SAVED_GENERATION requires F0_MANIFEST_SHA256")
        require_file(generation / "manifest.json", "F0_SAVED_GENERATION")
        prepare_binary(cls)
        directory = tempfile.TemporaryDirectory(prefix="saved-f0-regression-")
        cls.addClassCleanup(directory.cleanup)
        cls.directory = Path(directory.name)
        cls.spec = f0._spec(f0._binary())
        cls.function = FunctionId(BinaryId(f0.BINARY_SHA256), 0x8E58)
        cls.reference = AcquisitionRef(generation, pin or MANIFEST_PIN)
        saved = load(cls.reference, cls.function)
        versions = json.loads((cls.reference.generation / "manifest.json").read_bytes())["versions"]["tools"]

        def publish_saved(inputs, selection, root):
            if selection.name != inputs.spec.frontend:
                raise ValueError("Unexpected F0 frontend selection")
            return SimpleNamespace(
                reference=publish(inputs, saved.module, saved.cfg, saved.provenance, saved.report, versions, root),
                function=cls.function,
            )

        # The original assertions still exercise the real F0 publication and
        # reload of saved CIR; only the already-approved native lift is replaced.
        cls.enterClassContext(patch.object(f0, "acquire", side_effect=publish_saved))
