"""P0-B collector. Default is read-only dry-run; --execute authorizes fresh copies."""
import argparse
import ast
import configparser
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import pstats
import shutil
import subprocess
import sys
import time
import uuid

from baseline_inventory import full_inventory

from compare_baseline import (compare_icalls, compare_results, normalize_icalls,
                              normalize_results, read_json)

TARGET = Path(__file__).resolve().parents[1]
MIGRATION = TARGET.parent
LEGACY = MIGRATION / "EmTaint"
OLD_PYTHON = LEGACY / ".venv/Scripts/python.exe"
NEW_PYTHON = TARGET / ".venv/Scripts/python.exe"
REL_RESULT = Path("data/result_data/rv130_1_0_3_44.json")
REL_META = Path("data/ida_data/rv130_1_0_3_44")
REL_BINARY = Path("firmware-binaries/rv130_v44/httpd")
EXCLUDE = {".git", ".venv", "__pycache__"}


class IsolationValidated(Exception):
    """Finish validation-only mode through the same integrity/final-manifest path."""


def sha(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def write_json(path, value):
    # Only new artifact paths may be written by this collector.
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, ensure_ascii=False)
        stream.write("\n")


def inventory(root):
    return full_inventory(root)


def git(root, *arguments):
    return subprocess.check_output(["git", "--no-optional-locks", "-C", str(root),
                                    *arguments], encoding="utf-8")


def inside(path, root):
    try:
        Path(path).resolve().relative_to(Path(root).resolve())
        return True
    except ValueError:
        return False


def validate_run_root(run_root):
    resolved = run_root.resolve()
    if (not inside(resolved, MIGRATION / "baseline-work")
            or inside(resolved, LEGACY) or inside(resolved, TARGET)):
        raise RuntimeError("Invalid isolated run root: " + str(resolved))
    if (resolved / ".venv").exists():
        raise RuntimeError("Run copy must not contain a virtual environment")
    config = configparser.ConfigParser()
    config.read(resolved / "dataflow.conf")
    for key in ("DATA_PATH", "IDA_DATA_PATH", "RESULT_PATH"):
        value = config.get("result_config", key)
        if Path(value).is_absolute() or not inside(resolved / value, resolved):
            raise RuntimeError("Output/input config escapes the run copy: " + key)
    for relative in ("main.py", "dataflow.conf", REL_RESULT, REL_BINARY,
                     REL_META / "httpd_cfg.json", REL_META / "httpd_block_info.json",
                     REL_META / "httpd_icall.json"):
        if not (resolved / relative).is_file():
            raise RuntimeError("Run copy lacks required input: " + str(relative))


def copy_run(run_root, before):
    if run_root.exists():
        raise FileExistsError(str(run_root))
    run_root.mkdir(parents=True)
    copied = 0
    for record in before:
        relative = Path(record["path"])
        if any(part in EXCLUDE for part in relative.parts):
            continue
        source, destination = LEGACY / relative, run_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if (sha(destination) != record["sha256"]
                or os.path.samefile(source, destination)
                or destination.stat().st_nlink != 1):
            raise RuntimeError("Copy integrity/physical independence failed: " + str(relative))
        copied += 1
    validate_run_root(run_root)
    return copied


def child_environment():
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    env.pop("PYTHONPATH", None)
    env.pop("VIRTUAL_ENV", None)
    return env


def legacy_import_write_risks():
    """Static check only: importing the old angr can itself rewrite site-packages."""
    source = OLD_PYTHON.parent.parent / "Lib/site-packages/angr/sim_type.py"
    risks = []
    if source.exists():
        tree = ast.parse(source.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if ast.unparse(node.func) != "pycparser.ply.yacc.yacc":
                continue
            keywords = {keyword.arg: keyword.value for keyword in node.keywords}
            disabled = keywords.get("write_tables")
            if not (isinstance(disabled, ast.Constant) and disabled.value is False):
                risks.append({"file": str(source), "line": node.lineno,
                              "reason": "angr import uses PLY write_tables=True by default; parser-table isolation not validated"})
    return risks


def copy_bootstrap(run_root):
    source = TARGET / "scripts/legacy_readonly_bootstrap.py"
    destination = run_root / "_p0b_bootstrap.py"
    if destination.exists():
        raise FileExistsError(str(destination))
    shutil.copy2(source, destination)
    if sha(source) != sha(destination) or os.path.samefile(source, destination):
        raise RuntimeError("Bootstrap physical copy failed")


def require_isolation(proof):
    if (not proof or not proof.get("verified")
            or proof.get("bootstrap_sha256") != sha(TARGET / "scripts/legacy_readonly_bootstrap.py")):
        raise RuntimeError("Validated PLY isolation proof is required before legacy execution")


def bootstrap_command(run_root, archive, report, action, mode="disabled"):
    validate_run_root(run_root)
    if sha(run_root / "_p0b_bootstrap.py") != sha(TARGET / "scripts/legacy_readonly_bootstrap.py"):
        raise RuntimeError("Bootstrap changed since validation")
    return [str(OLD_PYTHON), "-B", str(run_root / "_p0b_bootstrap.py"),
            "--run-root", str(run_root), "--archive-root", str(archive),
            "--report", str(report), "--mode", mode, "--action", action]


def verify_legacy_step(before, status_before, archive, label):
    after = inventory(LEGACY)
    status = git(LEGACY, "status", "--porcelain=v1", "--untracked-files=all")
    unchanged = before == after and status == status_before
    a, b = {r["path"]: r for r in before}, {r["path"]: r for r in after}
    record = {"unchanged": unchanged, "file_count": len(after), "git_status": status,
              "inventory_sha256": hashlib.sha256(json.dumps(after, sort_keys=True).encode()).hexdigest(),
              "changes": [{"path": p, "before": a.get(p), "after": b.get(p)}
                          for p in sorted(a.keys() | b.keys()) if a.get(p) != b.get(p)]}
    write_json(archive / ("legacy-integrity-" + label + ".json"), record)
    if not unchanged:
        raise RuntimeError("Legacy integrity failure after " + label + "; no further legacy execution")
    print("Legacy content/mtime/Git unchanged after " + label, flush=True)


def validate_isolation(before, status_before, baseline, work):
    reports, values = {}, {}
    for mode in ("redirect", "disabled"):
        archive = baseline / "isolation" / mode
        archive.mkdir(parents=True)
        run_root = work / ("isolation-" + mode) / "EmTaint"
        copy_run(run_root, before)
        copy_bootstrap(run_root)
        command = bootstrap_command(run_root, archive, archive / "probe.bootstrap.json", "probe", mode)
        start = time.perf_counter()
        result = subprocess.run(command, cwd=run_root, env=child_environment(),
                                capture_output=True, timeout=300)
        (archive / "probe.stdout.txt").write_bytes(result.stdout)
        (archive / "probe.stderr.txt").write_bytes(result.stderr)
        write_json(archive / "command.json", {"command": command, "cwd": str(run_root),
                   "exit_code": result.returncode, "wall_seconds": time.perf_counter() - start})
        verify_legacy_step(before, status_before, archive, "probe")
        if result.returncode:
            raise RuntimeError("Isolation probe failed; see " + str(archive / "probe.stderr.txt"))
        reports[mode] = read_json(archive / "probe.bootstrap.json")
        values[mode] = json.loads(result.stdout)
        if not reports[mode]["ok"] or reports[mode]["violations"]:
            raise RuntimeError("Isolation probe attempted a prohibited write")
    reference_tables = [r for r in reports["redirect"]["cache_files"] if r["path"] == "parsetab.py"]
    isolated_tables = [r for r in reports["disabled"]["cache_files"]
                       if r["path"].endswith((".py", ".pyc", ".out"))]
    if (values["redirect"]["contract"] != values["disabled"]["contract"]
            or not reference_tables or isolated_tables):
        raise RuntimeError("Parser contract/table-generation isolation validation failed")
    proof = {"verified": True, "contract_equal": True, "legacy_unchanged_after_each_probe": True,
             "bootstrap_sha256": sha(TARGET / "scripts/legacy_readonly_bootstrap.py"),
             "contract": values["disabled"]["contract"],
             "redirected_tables": reference_tables, "disabled_tables": isolated_tables,
             "legacy_parsetab_sha256": sha(OLD_PYTHON.parent.parent / "Lib/site-packages/pycparser/parsetab.py")}
    write_json(baseline / "isolation-proof.json", proof)
    print("PLY isolation VERIFIED: equal parser contract; no legacy content/mtime changes", flush=True)
    return proof, work / "isolation-disabled/EmTaint"


def capture_environment(python, destination, run_root=None, proof=None, checkpoint=None):
    probe = """import sys,json,sysconfig,importlib
modules={}
for n in ['angr','pyvex','cle','archinfo','z3']:
 m=importlib.import_module(n)
 modules[n]={'version':str(getattr(m,'__version__',None)), 'file':m.__file__}
 if n=='z3': modules[n]['version']=m.get_version_string()
try:
 from angr import claripy
except ImportError:
 import claripy
x=claripy.BVS('probe',32,explicit_name=True)
print(json.dumps({'python':sys.version,'executable':sys.executable,'prefix':sys.prefix,
 'cache_tag':sys.implementation.cache_tag,'sys_path':sys.path,'modules':modules,
 'claripy':{'module':claripy.__name__,'file':getattr(claripy,'__file__',None),
 'type':str(type(x)),'bits':x.size(),'Load':hasattr(claripy,'Load'),
 'Store':hasattr(claripy,'Store'),'cache_key':hasattr(x,'cache_key'),
 'recursive_leaf_asts':hasattr(x,'recursive_leaf_asts')}}))
"""
    old = python == OLD_PYTHON
    if old:
        require_isolation(proof)
    command = (bootstrap_command(run_root, destination, destination / "environment.bootstrap.json", "environment")
               if old else [str(python), "-B", "-c", probe])
    process = subprocess.run(command, cwd=run_root if old else TARGET,
                             env=child_environment(), capture_output=True)
    (destination / "probe.stdout.txt").write_bytes(process.stdout)
    (destination / "probe.stderr.txt").write_bytes(process.stderr)
    if old:
        checkpoint(destination, "environment")
    if process.returncode:
        raise RuntimeError("Environment import failed: " + str(python))
    value = json.loads(process.stdout)
    write_json(destination / "environment.json", value["environment"] if old else value)
    for label, arguments in (("pip-freeze", ["freeze"]), ("pip-check", ["check"])):
        command = ((bootstrap_command(run_root, destination, destination / (label + ".bootstrap.json"), "module")
                    + ["--", "pip", *arguments, "--disable-pip-version-check"])
                   if old else [str(python), "-B", "-m", "pip", *arguments, "--disable-pip-version-check"])
        result = subprocess.run(command, cwd=run_root if old else TARGET,
                                env=child_environment(), capture_output=True)
        (destination / (label + ".stdout.txt")).write_bytes(result.stdout)
        (destination / (label + ".stderr.txt")).write_bytes(result.stderr)
        write_json(destination / (label + ".command.json"),
                   {"command": command, "exit_code": result.returncode})
        if old:
            checkpoint(destination, label)
        if result.returncode:
            raise RuntimeError(label + " failed: " + str(python))


def run_stage(run_root, archive, stage, profile, timeout, proof):
    import psutil  # Already installed in the target environment; never install packages.
    validate_run_root(run_root)
    require_isolation(proof)
    result_path = run_root / REL_RESULT
    previous_mtime = result_path.stat().st_mtime_ns
    bootstrap_report = archive / (stage + ".bootstrap.json")
    command = bootstrap_command(run_root, archive, bootstrap_report, "main")
    if profile:
        command += ["--profile-file", str(archive / (stage + ".prof"))]
    command += ["--", "-f", "./firmware-binaries/rv130_v44/httpd",
                "-n", "rv130", "-v", "1_0_3_44", "-i" if stage == "icall" else "-t"]
    start_utc = dt.datetime.now(dt.timezone.utc).isoformat()
    start = time.perf_counter()
    peak = 0
    timed_out = False
    with (archive / (stage + ".log")).open("xb") as log:
        process = subprocess.Popen(command, cwd=run_root, env=child_environment(),
                                   stdout=log, stderr=subprocess.STDOUT)
        monitor = psutil.Process(process.pid)
        while process.poll() is None:
            try:
                memory = monitor.memory_info()
                peak = max(peak, getattr(memory, "peak_wset", memory.rss))
            except psutil.NoSuchProcess:
                pass
            if time.perf_counter() - start > timeout:
                timed_out = True
                process.kill()
                process.wait()
                break
            time.sleep(0.2)
    record = {"command": command, "cwd": str(run_root), "started_at_utc": start_utc,
              "exit_code": process.returncode, "wall_seconds": time.perf_counter() - start,
              "peak_working_set_bytes": peak,
              "memory_scope": "Popen launcher only; excludes Windows venv worker/tree; not analysis peak",
              "profiled": profile, "timed_out": timed_out}
    write_json(archive / (stage + ".command.json"), record)
    if process.returncode or timed_out:
        raise RuntimeError("Stage failed; retained log: " + str(archive / (stage + ".log")))
    bootstrap = read_json(bootstrap_report)
    if not bootstrap["ok"] or bootstrap["violations"]:
        raise RuntimeError("Bootstrap rejected runtime writes")
    record["analysis_worker_memory"] = bootstrap["worker_memory"]
    if not result_path.exists() or result_path.stat().st_mtime_ns == previous_mtime:
        raise RuntimeError("Result was not rewritten by this invocation")
    text = (archive / (stage + ".log")).read_text(encoding="utf-8", errors="replace")
    output_paths = [line.split("Result-statistics-path:", 1)[1].strip()
                    for line in text.splitlines() if "Result-statistics-path:" in line]
    if not output_paths or any(Path(path).resolve() != result_path.resolve() for path in output_paths):
        raise RuntimeError("Log does not confirm the isolated output path")
    result = read_json(result_path)
    section = "icall" if stage == "icall" else "taint_1"
    if not isinstance(result.get(section), dict) or "time" not in result[section]:
        raise RuntimeError("Missing required output section: " + section)
    for source, name in ((result_path, stage + ".json"),
                         (run_root / REL_META / "httpd_icall.json", stage + "-targets.json")):
        destination = archive / name
        shutil.copy2(source, destination)
        if sha(source) != sha(destination):
            raise RuntimeError("Snapshot hash mismatch")
    record["result_sha256"] = sha(archive / (stage + ".json"))
    write_json(archive / (stage + ".verified.json"), record)
    if profile:
        summarize_profile(archive / (stage + ".prof"), archive / (stage + "-profile.json"), run_root)
    print(json.dumps({"stage": stage, "archive": str(archive), **record}), flush=True)
    return record


def summarize_profile(source, destination, run_root):
    stats = pstats.Stats(str(source))
    rows, modules = [], {}
    for (filename, line, name), (primitive, calls, exclusive, cumulative, callers) in stats.stats.items():
        relative = filename.replace(str(run_root), "<RUN_ROOT>")
        rows.append({"file": relative, "line": line, "function": name,
                     "primitive_calls": primitive, "total_calls": calls,
                     "exclusive_seconds": exclusive, "cumulative_seconds": cumulative})
        modules[relative] = modules.get(relative, 0.0) + exclusive
    write_json(destination, {"total_profile_seconds": stats.total_tt,
               "total_calls": stats.total_calls, "primitive_calls": stats.prim_calls,
               "top_cumulative": sorted(rows, key=lambda r: r["cumulative_seconds"], reverse=True)[:50],
               "top_exclusive": sorted(rows, key=lambda r: r["exclusive_seconds"], reverse=True)[:50],
               "modules_exclusive": sorted(modules.items(), key=lambda r: r[1], reverse=True),
               "note": "Cumulative rows overlap; do not sum them. Includes imports and unchanged debug logging."})


def compare_run(primary, candidate):
    return {stage: {
        "results": compare_results(read_json(primary / (stage + ".json")),
                                   read_json(candidate / (stage + ".json"))),
        "targets": compare_icalls(read_json(primary / (stage + "-targets.json")),
                                  read_json(candidate / (stage + "-targets.json")))}
        for stage in ("icall", "taint")}


def collect(args):
    for path in (LEGACY, OLD_PYTHON, NEW_PYTHON, LEGACY / REL_RESULT, LEGACY / REL_BINARY):
        if not path.exists():
            raise RuntimeError("Required path missing: " + str(path))
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:8]
    baseline = MIGRATION / "baselines/rv130_1_0_3_44" / stamp
    work = MIGRATION / "baseline-work/rv130_1_0_3_44" / stamp
    plan = {"execute": args.execute, "legacy_read_only": str(LEGACY),
            "baseline": str(baseline), "work": str(work),
            "repetitions": args.repetitions, "profile": args.profile,
            "sequence": ["-i", "-t"], "seed": "current dirty working tree and existing iCall file",
            "algorithm_changes": False, "dependency_installation": False,
            "detected_import_write_risks": legacy_import_write_risks(),
            "isolation_required": "validate redirected versus disabled PLY tables before ALL old imports",
            "validation_only": getattr(args, "validate_isolation_only", False)}
    print(json.dumps(plan, indent=2), flush=True)
    if not args.execute:
        return 0
    baseline.mkdir(parents=True, exist_ok=False)
    write_json(baseline / "plan.json", plan)
    manifest = {"schema_version": 1, "status": "started", "plan": plan, "runs": []}
    before = None
    status_before = git(LEGACY, "status", "--porcelain=v1", "--untracked-files=all")
    try:
        print("Hashing the entire legacy tree, including .git and .venv", flush=True)
        before = inventory(LEGACY)
        write_json(baseline / "file-inventory-before.json", before)
        manifest["legacy_commit"] = git(LEGACY, "rev-parse", "HEAD").strip()
        manifest["target_commit"] = git(TARGET, "rev-parse", "HEAD").strip()
        manifest["legacy_status_before"] = status_before
        manifest["target_status"] = git(TARGET, "status", "--porcelain=v1")
        manifest["binary_sha256"] = sha(LEGACY / REL_BINARY)
        manifest["preexisting_sha256"] = sha(LEGACY / REL_RESULT)
        manifest["hash_seed"] = os.environ.get("PYTHONHASHSEED", "unset; interpreter default")
        shutil.copy2(LEGACY / REL_RESULT, baseline / "preexisting.json")
        (baseline / "legacy-working-tree.diff").write_text(git(LEGACY, "diff", "--no-ext-diff"), encoding="utf-8")
        tooling = baseline / "collection-tooling"
        tooling.mkdir()
        for source in (TARGET / "scripts").glob("*.py"):
            shutil.copy2(source, tooling / source.name)
        shutil.copy2(TARGET / "scripts/legacy_baseline.ps1", tooling / "legacy_baseline.ps1")
        proof, probe_root = validate_isolation(before, status_before, baseline, work)
        manifest["isolation_proof"] = proof
        if getattr(args, "validate_isolation_only", False):
            raise IsolationValidated()

        def checkpoint(archive, label):
            verify_legacy_step(before, status_before, archive, label)

        environment = baseline / "environment"
        for label, python in (("legacy", OLD_PYTHON), ("target", NEW_PYTHON)):
            folder = environment / label
            folder.mkdir(parents=True)
            capture_environment(python, folder, probe_root, proof, checkpoint)
        patches = environment / "legacy-claripy-sources"
        patches.mkdir()
        for relative in ("ast/bv.py", "operations.py"):
            source = LEGACY / ".venv/Lib/site-packages/claripy" / relative
            shutil.copy2(source, patches / relative.replace("/", "_"))
        modes = [("reference" if i == 0 else "repeat-%02d" % i, False)
                 for i in range(args.repetitions)]
        if args.profile:
            modes.append(("profile", True))
        for label, profiled in modes:
            archive = baseline if label == "reference" else baseline / label
            if label != "reference":
                archive.mkdir()
            run_root = work / label / "EmTaint"
            copied = copy_run(run_root, before)
            copy_bootstrap(run_root)
            print("Physical copy verified: " + str(run_root), flush=True)
            input_files = inventory(run_root)
            write_json(archive / "run-inventory-before.json", input_files)
            run = {"label": label, "run_root": str(run_root), "copied_files": copied, "stages": {}}
            manifest["runs"].append(run)
            for stage in ("icall", "taint"):
                try:
                    run["stages"][stage] = run_stage(run_root, archive, stage, profiled, args.timeout, proof)
                finally:
                    checkpoint(archive, stage)
            write_json(archive / "run-inventory-after.json", inventory(run_root))
            if label != "reference":
                write_json(archive / "comparison.json", compare_run(baseline, archive))
        normalized = baseline / "normalized"
        normalized.mkdir()
        for stage in ("icall", "taint"):
            write_json(normalized / (stage + ".json"), normalize_results(read_json(baseline / (stage + ".json"))))
            write_json(normalized / (stage + "-targets.json"), normalize_icalls(read_json(baseline / (stage + "-targets.json"))))
        write_json(baseline / "historical-comparison.json",
                   compare_results(read_json(baseline / "preexisting.json"), read_json(baseline / "taint.json")))
        manifest["status"] = "collected"
    except IsolationValidated:
        manifest["status"] = "isolation_validated"
    except Exception as error:
        manifest["status"] = "failed"
        manifest["error"] = repr(error)
        raise
    finally:
        if before is not None:
            print("Verifying the entire legacy tree remains unchanged", flush=True)
            after = inventory(LEGACY)
            write_json(baseline / "file-inventory-after.json", after)
            manifest["legacy_status_after"] = git(LEGACY, "status", "--porcelain=v1", "--untracked-files=all")
            manifest["legacy_unchanged"] = before == after and status_before == manifest["legacy_status_after"]
            if not manifest["legacy_unchanged"]:
                manifest["status"] = "legacy_integrity_failure"
        manifest["finished_at_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        write_json(baseline / "manifest.json", manifest)
        print("MANIFEST=" + str(baseline / "manifest.json"), flush=True)
    if manifest["status"] not in ("collected", "isolation_validated"):
        raise RuntimeError(manifest["status"])
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--validate-isolation-only", action="store_true")
    parser.add_argument("--repetitions", type=int, choices=range(1, 6), default=2)
    parser.add_argument("--timeout", type=int, default=1800, help="Seconds per stage")
    return collect(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
