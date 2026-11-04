"""Verify the immutable legacy httpd baseline and optionally compare a candidate."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
WORKSPACE = ROOT.parent
sys.path.insert(0, str(ROOT / "scripts"))

from compare_baseline import compare_results, read_json


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def check_baseline(specification: Path, candidate: Path | None = None) -> dict[str, object]:
    """Return file-integrity, semantic-statistic, and optional candidate checks."""

    spec = read_json(specification)
    if spec.get("schema") != "emtaint-httpd-legacy-baseline-v1":
        raise ValueError("Unsupported httpd baseline schema")
    baseline = WORKSPACE / spec["baseline"]
    files = []
    for name, expected in sorted(spec["files"].items()):
        path = baseline / name
        actual = _sha256(path) if path.is_file() else None
        files.append({
            "name": name,
            "expected_sha256": expected.lower(),
            "actual_sha256": actual,
            "matched": actual == expected.lower(),
        })
    legacy = read_json(baseline / "taint.json")
    actual_stats = {
        name: legacy["taint_1"].get(name)
        for name in spec["taint_1"]
    }
    stats_equal = actual_stats == spec["taint_1"]
    comparison = None
    if candidate is not None:
        comparison = compare_results(legacy, read_json(candidate))
    passed = (
        all(item["matched"] for item in files)
        and stats_equal
        and (comparison is None or comparison["semantic_equal"])
    )
    return {
        "schema": "emtaint-httpd-baseline-check-v1",
        "baseline": str(baseline.resolve()),
        "files": files,
        "expected_statistics": spec["taint_1"],
        "actual_statistics": actual_stats,
        "statistics_equal": stats_equal,
        "candidate": None if candidate is None else str(candidate.resolve()),
        "comparison": comparison,
        "passed": passed,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--spec",
        type=Path,
        default=ROOT / "tests" / "fixtures" / "httpd_baseline_v1.json",
    )
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()
    report = check_baseline(arguments.spec, arguments.candidate)
    arguments.output.parent.mkdir(parents=True, exist_ok=True)
    arguments.output.write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
