"""P0-B v5: new physical control/observed copies, preserving every existing Golden."""
import argparse
import ast
import datetime as dt
import json
from pathlib import Path
import shutil
import subprocess
import sys
import uuid

import legacy_baseline as base


def observation_plan():
    records, hashes = [], {}
    for relative in ("dataflow/accurate_data_flow.py", "dataflow/data_trace.py", "dataflow/parse_ast.py"):
        path = base.LEGACY / relative
        hashes[relative] = base.sha(path)
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
        class Visitor(ast.NodeVisitor):
            def __init__(self):
                self.functions = []
            def visit_FunctionDef(self, node):
                self.functions.append(node)
                self.generic_visit(node)
                self.functions.pop()
            def visit_If(self, node):
                text = ast.unparse(node.test)
                selected = any(v in text for v in ("APTR_MAX", "MAX_LOOPS", "FUNC_MAX_TIMES"))
                selected |= "sim_action_len" in text and "> 2" in text
                selected |= "len(ls_actions) > 1" in text
                if selected and self.functions:
                    function = self.functions[-1]
                    threshold = 5 if "APTR_MAX" in text else (2 if "sim_action_len" in text and "> 2" in text else None)
                    records.append({"id": relative + ":" + str(node.lineno), "file": relative,
                                    "function": function.name, "function_line": function.lineno,
                                    "body_line": node.body[0].lineno, "test_start": node.lineno,
                                    "test_end": node.test.end_lineno, "condition": text,
                                    "ls_threshold": threshold, "action": type(node.body[0]).__name__})
                self.generic_visit(node)
        Visitor().visit(tree)
    return {"schema": "p0b-v5-source-gates-1", "source_hashes": hashes, "gates": records}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--timeout", type=int, default=1800)
    args = parser.parse_args()
    plan = observation_plan()
    print(json.dumps({"phase": "P0-B-v5", "execute": args.execute, "gates": plan["gates"],
                      "modes": ["control", "observed-01", "observed-02"], "sequence": ["-i", "-t"]}), flush=True)
    if not args.execute:
        return 0
    baselines = base.MIGRATION / "baselines"
    protected = base.inventory(baselines)
    target_venv = base.inventory(base.TARGET / ".venv")
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-v5-" + uuid.uuid4().hex[:8]
    root = baselines / "rv130_1_0_3_44" / stamp
    work = base.MIGRATION / "baseline-work/rv130_1_0_3_44" / stamp
    root.mkdir(parents=True, exist_ok=False)
    prefix = "rv130_1_0_3_44/" + stamp + "/"
    manifest = {"phase": "P0-B-v5", "status": "started", "runs": [], "seed": "warm-start current dirty tree and existing iCall"}
    status = base.git(base.LEGACY, "status", "--porcelain=v1", "--untracked-files=all")
    before = None
    print("BASELINE=" + str(root), flush=True)
    try:
        before = base.inventory(base.LEGACY)
        base.write_json(root / "legacy-before.json", before)
        base.write_json(root / "target-venv-before.json", target_venv)
        base.write_json(root / "protected-baselines-before.json", protected)
        base.write_json(root / "observer-plan.json", plan)
        manifest.update({"legacy_commit": base.git(base.LEGACY, "rev-parse", "HEAD").strip(),
                         "target_commit": base.git(base.TARGET, "rev-parse", "HEAD").strip(),
                         "legacy_status_before": status, "binary_sha256": base.sha(base.LEGACY / base.REL_BINARY),
                         "historical_sha256": base.sha(base.LEGACY / base.REL_RESULT)})
        shutil.copy2(base.LEGACY / base.REL_RESULT, root / "preexisting.json")
        tooling = root / "collection-tooling"
        tooling.mkdir()
        for source in (base.TARGET / "scripts").glob("*.py"):
            shutil.copy2(source, tooling / source.name)
        proof, probe_root = base.validate_isolation(before, status, root, work)
        manifest["isolation_proof"] = proof
        env = root / "environment/legacy"
        env.mkdir(parents=True)
        base.capture_environment(base.OLD_PYTHON, env, probe_root, proof,
                                 lambda folder, label: base.verify_legacy_step(before, status, folder, label))
        # Metadata only: target API conformance is the next authorized phase.
        command = [str(base.NEW_PYTHON), "-B", "-c",
                   "import sys,json,importlib.metadata as m; print(json.dumps({'executable':sys.executable,'python':sys.version,'packages':{n:m.version(n) for n in ['angr','claripy','pyvex','cle','archinfo','z3-solver']}}))"]
        result = subprocess.run(command, cwd=base.TARGET, env=base.child_environment(), capture_output=True, check=True)
        base.write_json(root / "environment/target.json", json.loads(result.stdout))
        for label in ("control", "observed-01", "observed-02"):
            archive = root / label
            archive.mkdir()
            run_root = work / label / "EmTaint"
            copied = base.copy_run(run_root, before)
            base.copy_bootstrap(run_root)
            shutil.copy2(base.TARGET / "scripts/legacy_observer.py", run_root / "_p0b_observer.py")
            if base.sha(run_root / "_p0b_observer.py") != base.sha(base.TARGET / "scripts/legacy_observer.py"):
                raise RuntimeError("Observer copy failed")
            base.write_json(archive / "observer-plan.json", plan)
            base.write_json(archive / "run-before.json", base.inventory(run_root))
            run = {"label": label, "run_root": str(run_root), "copied_files": copied, "stages": {}}
            manifest["runs"].append(run)
            print("RUN=" + label, flush=True)
            for stage in ("icall", "taint"):
                try:
                    run["stages"][stage] = base.run_stage(run_root, archive, stage, False, args.timeout, proof, observed=label != "control")
                finally:
                    base.verify_legacy_step(before, status, archive, stage)
                if label != "control":
                    metrics = base.read_json(archive / (stage + ".metrics.json"))
                    if not metrics["observation_complete"]:
                        raise RuntimeError("Incomplete observation; retain run and inspect metrics")
            base.write_json(archive / "run-after.json", base.inventory(run_root))
            comparison = base.compare_run(root / "control", archive)
            base.write_json(archive / "comparison.json", comparison)
            if not all(r["semantic_equal"] for s in comparison.values() for r in s.values()):
                raise RuntimeError("Instrumentation changed observable results")
        original = baselines / "rv130_1_0_3_44/20261028T051055Z-96d1c781"
        comparisons = base.compare_run(original, root / "control")
        base.write_json(root / "golden-comparison.json", comparisons)
        if not all(r["semantic_equal"] for s in comparisons.values() for r in s.values()):
            raise RuntimeError("Current control differs from existing Golden")
        manifest["status"] = "collected"
    except BaseException as error:
        manifest["status"] = "failed"
        manifest["error"] = repr(error)
        raise
    finally:
        integrity = {}
        if before is not None:
            after = base.inventory(base.LEGACY)
            base.write_json(root / "legacy-after.json", after)
            integrity["legacy"] = before == after and status == base.git(base.LEGACY, "status", "--porcelain=v1", "--untracked-files=all")
        venv_after = base.inventory(base.TARGET / ".venv")
        base.write_json(root / "target-venv-after.json", venv_after)
        integrity["target_venv"] = venv_after == target_venv
        golden_after = [r for r in base.inventory(baselines) if not r["path"].startswith(prefix)]
        base.write_json(root / "protected-baselines-after.json", golden_after)
        integrity["existing_baselines"] = protected == golden_after
        manifest["integrity"] = integrity
        if not all(integrity.values()):
            manifest["status"] = "integrity_failure"
        base.write_json(root / "manifest.json", manifest)
        print("MANIFEST=" + str(root / "manifest.json"), flush=True)
    if manifest["status"] != "collected":
        raise RuntimeError(manifest["status"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
