"""Isolated, resumable execution for an immutable alias-suite manifest."""

from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import threading
import time
from typing import Iterable

import psutil


def read_manifest(path: Path) -> dict[str, object]:
    """Read and minimally validate a v1 alias-suite manifest."""

    with path.open(encoding="utf-8") as stream:
        manifest = json.load(stream)
    if manifest.get("schema") != "emtaint-alias-suite-manifest-v1":
        raise ValueError("Unsupported alias-suite manifest schema")
    if not isinstance(manifest.get("samples"), list):
        raise ValueError("Alias-suite manifest samples must be a list")
    return manifest


def _peak_tree_rss(process: psutil.Process) -> int:
    processes = [process]
    try:
        processes.extend(process.children(recursive=True))
    except psutil.Error:
        pass
    total = 0
    for item in processes:
        try:
            total += item.memory_info().rss
        except psutil.Error:
            continue
    return total


def _execute(command: list[str], cwd: Path, timeout: float) -> dict[str, object]:
    started = time.perf_counter()
    child = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
    )
    monitored = psutil.Process(child.pid)
    stdout_chunks: list[str] = []
    stderr_chunks: list[str] = []

    def drain(stream, chunks: list[str]) -> None:
        while block := stream.read(64 * 1024):
            chunks.append(block)

    readers = (
        threading.Thread(
            target=drain, args=(child.stdout, stdout_chunks), daemon=True
        ),
        threading.Thread(
            target=drain, args=(child.stderr, stderr_chunks), daemon=True
        ),
    )
    for reader in readers:
        reader.start()
    peak = 0
    timed_out = False
    deadline = started + timeout
    while child.poll() is None:
        peak = max(peak, _peak_tree_rss(monitored))
        if time.perf_counter() >= deadline:
            timed_out = True
            child.terminate()
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
            break
        time.sleep(0.05)
    for reader in readers:
        reader.join()
    stdout = "".join(stdout_chunks)
    stderr = "".join(stderr_chunks)
    child.stdout.close()
    child.stderr.close()
    try:
        peak = max(peak, _peak_tree_rss(monitored))
    except psutil.Error:
        pass
    return {
        "command": command,
        "exit_code": child.returncode,
        "timed_out": timed_out,
        "wall_seconds": time.perf_counter() - started,
        "peak_working_set_bytes": peak,
        "stdout": stdout,
        "stderr": stderr,
    }


def evaluate_sample(
        sample: dict[str, object], execution: dict[str, object],
        report: dict[str, object] | None) -> dict[str, object]:
    """Combine process and semantic outcomes without treating incomplete as MAY."""

    marker_counts = sample["markers"]
    required = sum(
        int(marker_counts[name])
        for name in ("MUSTALIAS", "MAYALIAS", "NOALIAS", "PARTIALALIAS")
    )
    expected_xfail = sum(
        int(marker_counts[name])
        for name in ("EXPECTEDFAIL_MAYALIAS", "EXPECTEDFAIL_NOALIAS")
    )
    if report is None:
        return {
            "passed": False,
            "smoke_only": bool(sample["smoke_only"]),
            "required": required,
            "matched": 0,
            "expected_xfail": expected_xfail,
            "xfailed": 0,
            "xpassed": 0,
            "complete_required": 0,
            "missing_markers": required + expected_xfail,
            "extra_markers": 0,
            "reason_codes": [
                "TIMEOUT" if execution["timed_out"] else "PROCESS_FAILED"
            ],
        }
    observations = report.get("observations", [])
    required_observations = [
        item for item in observations
        if item.get("expected_status", "required") == "required"
    ]
    xfail_observations = [
        item for item in observations
        if item.get("expected_status") == "xfail"
    ]
    complete_required = sum(
        item.get("complete") is True for item in required_observations
    )
    observed_expected = sum(item.get("expected") is not None for item in observations)
    expected_total = required + expected_xfail
    missing = max(0, expected_total - observed_expected)
    extra = sum(item.get("expected") is None for item in observations)
    reasons = Counter(
        reason
        for item in observations
        for reason in item.get("reason_codes", [])
    )
    if missing:
        reasons["MARKER_MISSING"] += missing
    if extra:
        reasons["MARKER_EXTRA"] += extra
    smoke_only = bool(sample["smoke_only"])
    smoke_passed = smoke_only and not observations and not report.get("diagnostics")
    required_passed = (
        not smoke_only
        and int(report.get("matched", 0)) == required
        and complete_required == required
    )
    passed = (
        execution["exit_code"] == 0
        and not execution["timed_out"]
        and not missing
        and not extra
        and (smoke_passed or required_passed)
    )
    return {
        "passed": passed,
        "smoke_only": smoke_only,
        "required": required,
        "matched": int(report.get("matched", 0)),
        "expected_xfail": expected_xfail,
        "xfailed": sum(item.get("matched") is False for item in xfail_observations),
        "xpassed": sum(item.get("matched") is True for item in xfail_observations),
        "complete_required": complete_required,
        "missing_markers": missing,
        "extra_markers": extra,
        "reason_codes": dict(sorted(reasons.items())),
    }


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _load_completed(path: Path) -> dict[str, object]:
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def _environment() -> dict[str, object]:
    modules = {}
    for name in ("angr", "archinfo", "claripy", "cle", "psutil", "pyvex"):
        module = __import__(name)
        modules[name] = getattr(module, "__version__", "unknown")
    return {
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "modules": modules,
    }


def _prepare_native_cache(binary_analysis: Path) -> None:
    """Keep generated native FFI metadata inside the writable workspace."""

    cache = binary_analysis / ".p7-work" / "native-cache"
    cache.mkdir(parents=True, exist_ok=True)
    os.environ["TEMP"] = str(cache)
    os.environ["TMP"] = str(cache)


def _selected_samples(
        manifest: dict[str, object], suites: set[str], names: set[str]
) -> Iterable[dict[str, object]]:
    for sample in manifest["samples"]:
        if suites and sample["suite"] not in suites:
            continue
        if names and sample["sample"] not in names:
            continue
        yield sample


def run_alias_suite(
        *, manifest_path: Path, output: Path, workspace: Path,
        suites: set[str] | None = None, names: set[str] | None = None,
        timeout_seconds: float = 120.0, resume: bool = False) -> dict[str, object]:
    """Run selected samples serially and persist every outcome independently."""

    manifest = read_manifest(manifest_path)
    workspace = workspace.resolve()
    binary_analysis = workspace / "BinaryAnalysis"
    _prepare_native_cache(binary_analysis)
    if output.exists() and not resume:
        raise FileExistsError("Output directory exists; use --resume: " + str(output))
    output.mkdir(parents=True, exist_ok=True)
    _write_json(output / "manifest.json", manifest)
    _write_json(output / "environment.json", _environment())
    commands = []
    results = []
    for sample in _selected_samples(manifest, suites or set(), names or set()):
        sample_output = output / "samples" / sample["suite"] / (
            sample["sample"] + ".json"
        )
        if resume and sample_output.is_file():
            results.append(_load_completed(sample_output))
            continue
        source = workspace / sample["source"]
        binary = workspace / sample["binary"]
        command = [
            sys.executable,
            "-B",
            str(binary_analysis / "scripts" / "alias_benchmark.py"),
            "--source",
            str(source),
            "--binary",
            str(binary),
            "--json",
        ]
        execution = _execute(command, binary_analysis, timeout_seconds)
        commands.append({
            "suite": sample["suite"],
            "sample": sample["sample"],
            "command": command,
        })
        report = None
        parse_error = None
        if execution["stdout"].strip():
            try:
                report = json.loads(execution["stdout"])
            except json.JSONDecodeError as error:
                parse_error = str(error)
        outcome = evaluate_sample(sample, execution, report)
        if parse_error:
            outcome["passed"] = False
            outcome["reason_codes"] = {"REPORT_INVALID": 1}
        result = {
            "suite": sample["suite"],
            "sample": sample["sample"],
            "source_sha256": sample["source_sha256"],
            "binary_sha256": sample["binary_sha256"],
            "execution": execution,
            "report": report,
            "parse_error": parse_error,
            "outcome": outcome,
        }
        _write_json(sample_output, result)
        results.append(result)
    _write_json(output / "commands.json", commands)
    failures = [result for result in results if not result["outcome"]["passed"]]
    metrics = [{
        "suite": result["suite"],
        "sample": result["sample"],
        "wall_seconds": result["execution"]["wall_seconds"],
        "peak_working_set_bytes": result["execution"]["peak_working_set_bytes"],
        "timed_out": result["execution"]["timed_out"],
        "passed": result["outcome"]["passed"],
    } for result in results]
    metrics_path = output / "metrics.jsonl"
    metrics_path.write_text(
        "".join(json.dumps(item, sort_keys=True) + "\n" for item in metrics),
        encoding="utf-8",
    )
    reason_counts = Counter()
    for result in results:
        reasons = result["outcome"]["reason_codes"]
        if isinstance(reasons, list):
            reason_counts.update(reasons)
        else:
            reason_counts.update(reasons)
    _write_json(output / "failures.json", failures)
    _write_json(output / "unknown-reasons.json", dict(sorted(reason_counts.items())))
    aggregate = {
        "schema": "emtaint-alias-suite-run-v1",
        "selected_samples": len(results),
        "passed_samples": sum(result["outcome"]["passed"] for result in results),
        "failed_samples": len(failures),
        "required": sum(result["outcome"]["required"] for result in results),
        "matched": sum(result["outcome"]["matched"] for result in results),
        "complete_required": sum(
            result["outcome"]["complete_required"] for result in results
        ),
        "expected_xfail": sum(
            result["outcome"]["expected_xfail"] for result in results
        ),
        "xfailed": sum(result["outcome"]["xfailed"] for result in results),
        "xpassed": sum(result["outcome"]["xpassed"] for result in results),
        "smoke_only": sum(result["outcome"]["smoke_only"] for result in results),
        "missing_markers": sum(
            result["outcome"]["missing_markers"] for result in results
        ),
        "extra_markers": sum(
            result["outcome"]["extra_markers"] for result in results
        ),
        "timed_out": sum(result["execution"]["timed_out"] for result in results),
        "passed": not failures,
    }
    _write_json(output / "aggregate.json", aggregate)
    return aggregate
