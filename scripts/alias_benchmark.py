"""Command-line runner for source-annotated alias benchmarks."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from emtaint.analysis.aliasing import analyze_alias_benchmark


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Classify NOALIAS/MAYALIAS/MUSTALIAS marker calls"
    )
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--json", action="store_true")
    arguments = parser.parse_args()
    report = analyze_alias_benchmark(arguments.source, arguments.binary)
    if arguments.json:
        print(json.dumps(report.as_dict(), indent=2, sort_keys=True))
    else:
        for item in report.observations:
            line = "?" if item.source_line is None else str(item.source_line)
            status = "PASS" if item.matched else "FAIL"
            print(
                f"{status} line {line}: {item.left}, {item.right} -> "
                f"{item.predicted} at {item.site:#x}"
            )
        print(f"matched {report.matched}/{report.total}")
        for diagnostic in report.diagnostics:
            print("diagnostic: " + diagnostic)
    return 0 if report.matched == report.total else 1


if __name__ == "__main__":
    raise SystemExit(main())
