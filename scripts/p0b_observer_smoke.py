"""Python 3.7 native observer fixture in an existing new RunRoot; no CLI analysis."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import types

from p1_runtime import ProbeWriteGuard
from legacy_readonly_bootstrap import install_ply_isolation


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--run-root", type=Path, required=True)
    p.add_argument("--archive", type=Path, required=True)
    p.add_argument("--plan", type=Path, required=True)
    a = p.parse_args()
    root, archive = a.run_root.resolve(), a.archive.resolve()
    migration = Path(__file__).resolve().parents[2]
    root.relative_to(migration / "baseline-work")
    archive.relative_to(migration / "baselines")
    if Path.cwd().resolve() != root or not archive.is_dir():
        raise RuntimeError("Fixture requires copied RunRoot CWD and fresh archive")
    cache = archive / "cache"
    cache.mkdir(exist_ok=False)
    for key in ("TEMP", "TMP", "TMPDIR"):
        os.environ[key] = str(cache)
    tempfile.tempdir = str(cache)
    sys.dont_write_bytecode = True
    guard = ProbeWriteGuard([archive]).install()
    observer = None
    try:
        install_ply_isolation(cache, "disabled")
        sys.path.insert(0, str(root))
        runpy.run_path(str(root / "main.py"), run_name="observer_fixture_imports_only")
        spec = importlib.util.spec_from_file_location("observer_fixture", str(root / "_p0b_observer.py"))
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        observer = module.LegacyObserver(root, a.plan, archive / "fixture.metrics.json")
        observer._install()
        import claripy
        from dataflow.accurate_data_flow import AccurateDataFlow
        from dataflow.data_trace import FastSearch
        plan = json.loads(a.plan.read_text(encoding="utf-8"))
        coverage = []
        for gate in plan["gates"]:
            owner = AccurateDataFlow if "accurate_data_flow" in gate["file"] else FastSearch
            function = getattr(owner, gate["function"])
            while hasattr(function, "__wrapped__"):
                function = function.__wrapped__
            key = (function.__code__.co_filename, function.__code__.co_firstlineno)
            coverage.append({"id": gate["id"], "registered": key in observer.lookup})
        value = claripy.BVS("fixture_pointer", 32, explicit_name=True)
        for _ in range(3):
            value = claripy.Load(value, 32)
        trace = types.SimpleNamespace(expr=types.SimpleNamespace(data_type="Aptr", value=value, store_location=[]))
        action = types.SimpleNamespace(code_location=(0, 0))
        engine = AccurateDataFlow.__new__(AccurateDataFlow)
        output = engine._find_store_use_v1(action, "unused", trace)
        metrics = observer.stop()
        observer = None
        gate = next(g for g in metrics["gates"] if g["definition"]["id"].endswith(":709"))
        result = {"registered_gates": coverage, "forced_native_gate_hits": gate["hits"],
                  "forced_native_aptr_limit_hits": gate["aptr_limit_hits"],
                  "unchanged_return": output == [], "violations": guard.violations}
        with (archive / "report.json").open("x", encoding="utf-8") as stream:
            json.dump(result, stream, indent=2)
        if not all(v["registered"] for v in coverage) or gate["aptr_limit_hits"] != 1 or output != [] or guard.violations:
            raise RuntimeError("Observer did not observe the known native threshold branch")
        print(json.dumps(result), flush=True)
    finally:
        if observer is not None:
            observer.stop()
        guard.restore()


if __name__ == "__main__":
    main()
