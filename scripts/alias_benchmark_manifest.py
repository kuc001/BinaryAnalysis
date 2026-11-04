"""Generate the immutable four-suite alias benchmark input manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(ROOT))

from alias_suite_manifest import build_alias_suite_manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    manifest = build_alias_suite_manifest(WORKSPACE)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(
        "wrote " + str(len(manifest["samples"]))
        + " samples to " + str(arguments.output)
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
