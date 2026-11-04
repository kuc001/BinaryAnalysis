"""Run the immutable source-annotated alias suites in isolated processes."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(ROOT))

from alias_suite_runner import run_alias_suite


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--suite", action="append", default=[])
    parser.add_argument("--sample", action="append", default=[])
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    parser.add_argument("--jobs", type=int, default=1)
    parser.add_argument("--resume", action="store_true")
    arguments = parser.parse_args()
    if arguments.jobs != 1:
        parser.error("Correctness baseline currently requires --jobs 1")
    aggregate = run_alias_suite(
        manifest_path=arguments.manifest.resolve(),
        output=arguments.output.resolve(),
        workspace=WORKSPACE,
        suites=set(arguments.suite),
        names=set(arguments.sample),
        timeout_seconds=arguments.timeout_seconds,
        resume=arguments.resume,
    )
    print(json.dumps(aggregate, indent=2, sort_keys=True))
    return 0 if aggregate["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
