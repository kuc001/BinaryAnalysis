"""Isolated, resumable execution for an immutable alias-suite manifest."""

from __future__ import annotations

from collections import Counter
import hashlib
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

from scripts.alias_benchmark_analysis import (
    MARKERS, matches_expectation, parse_alias_expectations,
)


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
        incoherent = not bool(sample.get("binary_marker_inventory_complete", True))
        return {
            "passed": False,
            "input_incoherent": incoherent,
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
                "TIMEOUT" if execution["timed_out"] else "PROCESS_FAILED",
                *(["INPUT_INCOHERENT"] if incoherent else []),
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
    input_incoherent = not bool(sample.get("binary_marker_inventory_complete", True))
    if input_incoherent:
        reasons["INPUT_INCOHERENT"] += 1
        passed = False
    return {
        "passed": passed,
        "input_incoherent": input_incoherent,
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


def _attach_oracle(report: dict[str, object], source: Path) -> dict[str, object]:
    """Compare binary-only CLI observations with source labels after analysis."""

    expected = parse_alias_expectations(source)
    by_marker = {
        marker: [item for item in expected if item.marker == marker]
        for marker in MARKERS
    }
    indexes = {marker: 0 for marker in MARKERS}
    observations = []
    for original in report.get("observations", ()):
        item = dict(original)
        marker = item["observer"]
        position = indexes[marker]
        candidates = by_marker[marker]
        oracle = candidates[position] if position < len(candidates) else None
        indexes[marker] += 1
        item["expected"] = oracle.kind if oracle else None
        item["expected_status"] = oracle.status if oracle else "required"
        item["exact_matched"] = (
            oracle is not None and item["complete"]
            and item["predicted"] == oracle.kind
        )
        item["matched"] = (
            oracle is not None and matches_expectation(
                oracle.kind, item["predicted"], item["complete"]
            )
        )
        observations.append(item)
    return {
        **report,
        "observations": observations,
        "matched": sum(
            item["matched"] and item["expected_status"] == "required"
            for item in observations
        ),
        "strict_matched": sum(
            item["exact_matched"] and item["expected_status"] == "required"
            for item in observations
        ),
        "refined_may": sum(
            item["expected"] == "MAYALIAS"
            and item["predicted"] == "MUSTALIAS"
            and item["complete"]
            and item["expected_status"] == "required"
            for item in observations
        ),
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


def _code_sha256(binary_analysis: Path) -> str:
    """Fingerprint the Python analysis and the test adapter for run identity."""

    paths = sorted((binary_analysis / "emtaint").rglob("*.py"))
    paths.extend(
        binary_analysis / "scripts" / name
        for name in (
            "alias_benchmark_analysis.py",
            "alias_suite_manifest.py",
            "alias_suite_runner.py",
        )
    )
    digest = hashlib.sha256()
    for path in paths:
        digest.update(path.relative_to(binary_analysis).as_posix().encode())
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def _environment(binary_analysis: Path) -> dict[str, object]:
    modules = {}
    for name in ("angr", "archinfo", "claripy", "cle", "psutil", "pyvex"):
        module = __import__(name)
        modules[name] = getattr(module, "__version__", "unknown")
    return {
        "python": sys.version,
        "executable": sys.executable,
        "platform": platform.platform(),
        "modules": modules,
        "code_sha256": _code_sha256(binary_analysis),
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
    environment = _environment(binary_analysis)
    if resume and output.exists():
        prior_environment = output / "environment.json"
        if prior_environment.is_file():
            recorded = _load_completed(prior_environment)
            if recorded.get("code_sha256") != environment["code_sha256"]:
                raise ValueError("Cannot resume an unverified or changed code snapshot")
        prior_manifest = output / "manifest.json"
        if prior_manifest.is_file() and _load_completed(prior_manifest) != manifest:
            raise ValueError("Cannot resume with a changed alias-suite manifest")
    output.mkdir(parents=True, exist_ok=True)
    _write_json(output / "manifest.json", manifest)
    _write_json(output / "environment.json", environment)
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
            "-m",
            "emtaint",
            "-a",
            "-f",
            str(binary),
            "--discover-alias-calls",
            "--output",
            str(output / "queries" / sample["suite"] / sample["sample"]),
        ]
        for marker in MARKERS:
            command.extend(("--observe-call", marker))
        execution = _execute(command, binary_analysis, timeout_seconds)
        if _code_sha256(binary_analysis) != environment["code_sha256"]:
            raise RuntimeError(
                "Analysis code changed during sample " + sample["sample"]
            )
        commands.append({
            "suite": sample["suite"],
            "sample": sample["sample"],
            "command": command,
        })
        report = None
        parse_error = None
        if execution["stdout"].strip():
            try:
                report = _attach_oracle(json.loads(execution["stdout"]), source)
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
    verifiable = [
        result for result in results
        if not result["outcome"].get("input_incoherent")
    ]
    aggregate = {
        "schema": "emtaint-alias-suite-run-v1",
        "selected_samples": len(results),
        "passed_samples": sum(result["outcome"]["passed"] for result in results),
        "failed_samples": len(failures),
        "input_incoherent_samples": sum(
            bool(result["outcome"].get("input_incoherent")) for result in results
        ),
        "verifiable_samples": len(verifiable),
        "passed_verifiable_samples": sum(
            result["outcome"]["passed"] for result in verifiable
        ),
        "verifiable_required": sum(
            result["outcome"]["required"] for result in verifiable
        ),
        "verifiable_matched": sum(
            result["outcome"]["matched"] for result in verifiable
        ),
        "verifiable_passed": all(
            result["outcome"]["passed"] for result in verifiable
        ),
        "required": sum(result["outcome"]["required"] for result in results),
        "matched": sum(result["outcome"]["matched"] for result in results),
        "strict_matched": sum(
            int(result["report"].get("strict_matched", 0))
            for result in results if result["report"] is not None
        ),
        "refined_may": sum(
            int(result["report"].get("refined_may", 0))
            for result in results if result["report"] is not None
        ),
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
