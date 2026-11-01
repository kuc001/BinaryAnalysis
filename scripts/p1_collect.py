"""P1 API evidence only: no firmware analyses, dependency installs, or Golden writes."""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import subprocess
import shutil
import time
import uuid

from baseline_inventory import full_inventory
from legacy_baseline import git, sha, write_json

TARGET = Path(__file__).resolve().parents[1]
LEGACY = TARGET.parent / "EmTaint"


def run_probe(root, label, case):
    folder = root / label / case
    folder.mkdir(parents=True, exist_ok=False)
    cache = folder / "cache"
    cache.mkdir()
    interpreter = (LEGACY if label == "legacy" else TARGET) / ".venv/Scripts/python.exe"
    command = [str(interpreter), "-B", str(TARGET / "scripts/p1_probe.py"),
               "--environment", label, "--case", case, "--cache", str(cache),
               "--report", str(folder / "report.json")]
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
    start = time.monotonic()
    timed_out = False
    with (folder / "stdout.jsonl").open("xb") as out, (folder / "stderr.txt").open("xb") as err:
        process = subprocess.Popen(command, cwd=TARGET, env=env, stdout=out, stderr=err)
        try:
            exit_code = process.wait(timeout=90)
        except subprocess.TimeoutExpired:
            timed_out = True
            import sys
            sys.path.insert(0, str(TARGET))
            from emtaint.solver.process_port import terminate_tree
            terminate_tree(process)
            exit_code = process.wait()
    receipt = {"command": command, "cwd": str(TARGET), "exit_code": exit_code,
               "exit_hex": hex(exit_code & 0xffffffff), "timed_out": timed_out,
               "wall_seconds": time.monotonic() - start,
               "report_exists": (folder / "report.json").exists()}
    write_json(folder / "command.json", receipt)
    print(json.dumps({"environment": label, "case": case, **receipt}), flush=True)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--environments", nargs="+", choices=("legacy", "target"), default=["legacy", "target"])
    parser.add_argument("--cases", nargs="+", default=["expressions", "memory-markers", "sat", "unsat", "z3-direct", "z3-preload"])
    args = parser.parse_args()
    if not args.execute:
        print("Dry run: fresh .p1-work/<UTC-ID>, isolated old/new API probes; no -i/-t")
        return 0
    root = TARGET / ".p1-work" / (dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
                                  + "-" + uuid.uuid4().hex[:8])
    root.mkdir(parents=True, exist_ok=False)
    tooling = root / "tooling"
    tooling.mkdir()
    for name in ("p1_probe.py", "p1_collect.py", "p1_runtime.py", "legacy_readonly_bootstrap.py", "baseline_inventory.py"):
        shutil.copy2(TARGET / "scripts" / name, tooling / name)
    shutil.copy2(TARGET / "emtaint/solver/backends/ast_tools.py", tooling / "ast_tools.py")
    manifest = {"phase": "P1", "target_commit": git(TARGET, "rev-parse", "HEAD").strip(),
                "legacy_commit": git(LEGACY, "rev-parse", "HEAD").strip(), "probes": []}
    print("EVIDENCE=" + str(root), flush=True)
    roots = {"legacy": LEGACY, "target-venv": TARGET / ".venv",
             "golden": TARGET.parent / "baselines"}
    before = {}
    try:
        manifest["legacy_git_before"] = git(LEGACY, "status", "--porcelain=v1", "--untracked-files=all")
        for name, path in roots.items():
            print("Inventory before: " + name, flush=True)
            before[name] = full_inventory(path)
            write_json(root / (name + "-before.json"), before[name])
        for case in args.cases:
            for label in args.environments:
                receipt = run_probe(root, label, case)
                manifest["probes"].append({"environment": label, "case": case, **receipt})
                # Every old import must leave the entire legacy tree unchanged.
                if label == "legacy":
                    after = full_inventory(LEGACY)
                    if after != before["legacy"]:
                        write_json(root / ("legacy-failure-" + case + ".json"), after)
                        raise RuntimeError("Legacy changed; stopping all further native probes")
                    print("Legacy unchanged after " + case, flush=True)
        manifest["status"] = "probed"
    finally:
        manifest["integrity"] = {}
        for name, original in before.items():
            print("Inventory after: " + name, flush=True)
            after = full_inventory(roots[name])
            write_json(root / (name + "-after.json"), after)
            manifest["integrity"][name] = {"unchanged": original == after, "files": len(after)}
        manifest["legacy_git_after"] = git(LEGACY, "status", "--porcelain=v1", "--untracked-files=all")
        manifest["legacy_git_unchanged"] = manifest.get("legacy_git_before") == manifest["legacy_git_after"]
        write_json(root / "manifest.json", manifest)
        print("MANIFEST=" + str(root / "manifest.json"), flush=True)
    if not manifest["legacy_git_unchanged"] or not all(r["unchanged"] for r in manifest["integrity"].values()):
        raise RuntimeError("Integrity verification failed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
