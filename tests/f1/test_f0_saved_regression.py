"""Run the existing F0 assertions on saved records without restarting native acquisition."""
import json
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from emtaint.artifacts import AcquisitionRef, load, publish
from emtaint.core import BinaryId, FunctionId

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests/f0"))
try:
    import test_acquisition as f0
finally:
    sys.path.pop(0)

SAVED = ROOT / ".f0-runtime/artifacts/generation-a7470d49744a41d99fc673785fb76f73"
MANIFEST_PIN = "6dce3efbdf607764bb9a9ffb8652d9204f9508a0952327e97525a2c64be7147c"


class SavedF0Regression(f0.RealAcquisitionTests):
    @classmethod
    def setUpClass(cls) -> None:
        directory = tempfile.TemporaryDirectory(prefix="saved-f0-regression-")
        cls.addClassCleanup(directory.cleanup)
        cls.directory = Path(directory.name)
        cls.spec = f0._spec(f0._binary())
        cls.function = FunctionId(BinaryId(f0.BINARY_SHA256), 0x8E58)
        cls.reference = AcquisitionRef(Path(os.environ.get("F0_SAVED_GENERATION", SAVED)), MANIFEST_PIN)
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


def load_tests(loader: unittest.TestLoader, tests: unittest.TestSuite, pattern: str | None) -> unittest.TestSuite:
    """Include the four unchanged F0 Project tests with the nine saved-asset cases."""
    tests.addTests(loader.loadTestsFromTestCase(f0.ProjectInputTests))
    return tests
