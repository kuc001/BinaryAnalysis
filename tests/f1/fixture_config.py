"""External evidence policy for the F0/F1 regression suites."""
import os
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]


def require_file(path: Path, setting: str) -> None:
    """Skip absent evidence in developer runs and fail formal acceptance."""
    if path.is_file():
        return
    message = f"Missing evidence at {path}; configure {setting}"
    if os.environ.get("F1_STRICT_ACCEPTANCE") == "1":
        raise AssertionError(f"BLOCKED: {message}")
    raise unittest.SkipTest(message)
