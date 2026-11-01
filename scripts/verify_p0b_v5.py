"""Independent P0-B v5 acceptance; append new sidecars, never edit raw metrics/Golden."""
from collections import Counter
import argparse
import json
from pathlib import Path

import legacy_baseline as base


def reviewed_status(row):
    if row["error"] is not None:
        return row["status"]
    raw = row["raw"]
    if any(r["status"] == "unknown" for r in raw):
        return "TIMEOUT" if any("timeout" in (r.get("reason") or "").lower() for r in raw) else "UNKNOWN"
    # A successful model enumeration may finish by proving no more models exist.
    if row["method"] != "satisfiable" and raw:
        return "SAT" if any(r["status"] == "sat" for r in raw) else "UNKNOWN"
    return row["status"]


def verify(root):
    root = Path(root).resolve()
    root.relative_to(base.MIGRATION / "baselines")
    manifest = base.read_json(root / "manifest.json")
    if manifest["status"] != "collected" or not all(manifest["integrity"].values()):
        raise RuntimeError("Collection/integrity Gate failed")
    for left, right in (("legacy-before.json", "legacy-after.json"),
                        ("target-venv-before.json", "target-venv-after.json"),
                        ("protected-baselines-before.json", "protected-baselines-after.json")):
        if base.read_json(root / left) != base.read_json(root / right):
            raise RuntimeError("Protected inventory differs: " + left)
    golden = base.MIGRATION / "baselines/rv130_1_0_3_44/20261028T051055Z-96d1c781"
    summary = {"phase": "P0-B-v5", "gate": "PASS", "integrity": manifest["integrity"],
               "warm_start": True, "stages": [], "telemetry_repeat_differences": {},
               "metrics_scope": "observed roots/selected 12 gates; not whole-program semantic completeness"}
    for run in manifest["runs"]:
        archive = root / run["label"]
        comparison = base.compare_run(root / "control", archive)
        if comparison != base.read_json(archive / "comparison.json"):
            raise RuntimeError("Archived comparison does not match raw snapshots")
        if not all(r["semantic_equal"] for v in comparison.values() for r in v.values()):
            raise RuntimeError("Observed results differ")
        for stage in ("icall", "taint"):
            receipt = base.read_json(archive / (stage + ".verified.json"))
            if receipt["exit_code"] or receipt["result_sha256"] != base.sha(archive / (stage + ".json")):
                raise RuntimeError("Stage result/receipt mismatch")
            boot = base.read_json(archive / (stage + ".bootstrap.json"))
            if not boot["ok"] or boot["violations"]:
                raise RuntimeError("Isolation failure")
            row = {"label": run["label"], "stage": stage, "wall_seconds": receipt["wall_seconds"],
                   "worker_peak_bytes": receipt["analysis_worker_memory"]["peak_working_set_bytes"],
                   "result_diff": comparison[stage]}
            if run["label"] != "control":
                metrics = base.read_json(archive / (stage + ".metrics.json"))
                if not metrics["observation_complete"] or metrics["observer_errors"]:
                    raise RuntimeError("Observation incomplete")
                if boot["observer_sha256"] != base.sha(root / "collection-tooling/legacy_observer.py"):
                    raise RuntimeError("Actual observer differs from archived tooling")
                queries = [json.loads(line) for line in (archive / (stage + ".metrics.queries.jsonl")).read_text().splitlines()]
                if len(queries) != metrics["frontend_calls"]:
                    raise RuntimeError("Incomplete query journal")
                counts = Counter(reviewed_status(q) for q in queries)
                public = [q for q in queries if q["layer"] == "public_solver"]
                row.update({"expression_maxima": {k: v["maxima"] for k, v in metrics["expressions"].items()},
                            "counts": metrics["counts"], "gates": metrics["gates"],
                            "raw_smt_checks": metrics["raw_smt_checks"], "raw_status_counts": metrics["raw_status_counts"],
                            "frontend_events": len(queries), "public_events": len(public),
                            "top_level_public_queries": sum(q["parent_id"] is None for q in public),
                            "reviewed_status_counts": dict(counts),
                            "status_review_corrections": [{"query_id": q["id"], "before": q["status"], "after": reviewed_status(q)}
                                                          for q in queries if q["status"] != reviewed_status(q)]})
            summary["stages"].append(row)
    final_diff = base.compare_run(golden, root / "control")
    if final_diff != base.read_json(root / "golden-comparison.json") or not all(
            r["semantic_equal"] for v in final_diff.values() for r in v.values()):
        raise RuntimeError("Existing Golden differs")
    smoke = base.read_json(root / "observer-selftest/report.json")
    if not all(r["registered"] for r in smoke["registered_gates"]) or smoke["forced_native_aptr_limit_hits"] != 1 or not smoke["unchanged_return"] or smoke["violations"]:
        raise RuntimeError("Native gate observation fixture failed")
    summary["native_gate_fixture"] = smoke
    for stage in ("icall", "taint"):
        pairs = [s for s in summary["stages"] if s["stage"] == stage and s["label"] != "control"]
        def stable(s):
            return {k: s[k] for k in ("expression_maxima", "raw_smt_checks", "raw_status_counts", "public_events", "top_level_public_queries")}
        summary["telemetry_repeat_differences"][stage] = base.compare_results(stable(pairs[0]), stable(pairs[1]))
    base.write_json(root / "validation-v5.json", summary)
    return summary


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("archive", type=Path)
    value = verify(p.parse_args().archive)
    print(json.dumps({"gate": value["gate"], "stages": len(value["stages"]), "integrity": value["integrity"]}))
