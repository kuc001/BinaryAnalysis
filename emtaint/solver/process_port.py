"""One target solver query per child process; native failure cannot kill the caller."""
import json
import os
from pathlib import Path
import subprocess
import time
import uuid

import psutil

from .port import SolverQuery, SolverResult, SolverStatus, UnsupportedQuery

TARGET = Path(__file__).resolve().parents[2]


def terminate_tree(process):
    """Windows venv launchers have an actual Python child; kill both on deadline."""
    killed = []
    try:
        parent = psutil.Process(process.pid)
        children = parent.children(recursive=True)
    except psutil.NoSuchProcess:
        children = []
    for child in reversed(children):
        try:
            child.kill()
            killed.append(child.pid)
        except psutil.NoSuchProcess:
            pass
    if process.poll() is None:
        process.kill()
        killed.append(process.pid)
    process.wait()
    psutil.wait_procs(children, timeout=5)
    return killed


class SubprocessSolverPort:
    def __init__(self, work_root=None, wall_timeout=None):
        self.work_root = Path(work_root or TARGET / ".p1-work/solver-requests").resolve()
        self.work_root.relative_to(TARGET / ".p1-work")
        if wall_timeout is not None and wall_timeout <= 0:
            raise ValueError("Positive wall timeout required")
        self.wall_timeout = wall_timeout

    def solve(self, query: SolverQuery) -> SolverResult:
        try:
            query.validate()
        except UnsupportedQuery as error:
            return SolverResult(SolverStatus.UNSUPPORTED, reason=str(error), origin=query.origin)
        except ValueError as error:
            return SolverResult(SolverStatus.ERROR, reason=str(error), origin=query.origin)
        folder = self.work_root / uuid.uuid4().hex
        folder.mkdir(parents=True, exist_ok=False)
        (folder / "cache").mkdir()
        with (folder / "request.json").open("x", encoding="utf-8") as stream:
            json.dump(query.to_dict(), stream)
        command = [str(TARGET / ".venv/Scripts/python.exe"), "-B",
                   str(TARGET / "scripts/p1_solver_worker.py"), "--folder", str(folder)]
        env = os.environ.copy()
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env.pop("PYTHONPATH", None)
        env.pop("VIRTUAL_ENV", None)
        deadline = self.wall_timeout if self.wall_timeout is not None else query.timeout_ms / 1000 + 30
        started = time.monotonic()
        killed = []
        with (folder / "stdout.jsonl").open("xb") as out, (folder / "stderr.txt").open("xb") as err:
            try:
                process = subprocess.Popen(command, cwd=TARGET, env=env, stdout=out, stderr=err)
            except OSError as error:
                with (folder / "process.json").open("x", encoding="utf-8") as stream:
                    json.dump({"command": command, "launch_error": str(error)}, stream)
                return SolverResult(SolverStatus.ERROR, reason="Worker launch failed: " + str(error),
                                    origin=query.origin, evidence=str(folder))
            try:
                process.wait(timeout=deadline)
            except subprocess.TimeoutExpired:
                killed = terminate_tree(process)
        receipt = {"command": command, "cwd": str(TARGET), "exit_code": process.returncode,
                   "wall_seconds": time.monotonic() - started, "wall_timeout_seconds": deadline,
                   "deadline_exceeded": bool(killed), "killed_processes": killed}
        with (folder / "process.json").open("x", encoding="utf-8") as stream:
            json.dump(receipt, stream, indent=2)
        if killed:
            return SolverResult(SolverStatus.TIMEOUT, reason="Parent wall deadline exceeded; worker tree terminated",
                                origin=query.origin, evidence=str(folder), exit_code=process.returncode)
        if process.returncode:
            native = process.returncode < 0 or (process.returncode & 0xffffffff) >= 0x80000000
            return SolverResult(SolverStatus.CRASH if native else SolverStatus.ERROR,
                                reason="Worker exited " + hex(process.returncode & 0xffffffff) + "; inspect stderr/checkpoints",
                                origin=query.origin, evidence=str(folder), exit_code=process.returncode)
        try:
            data = json.loads((folder / "result.json").read_text(encoding="utf-8"))
            result = SolverResult.from_dict(data)
            if (any(type(v) is not int for v in result.values)
                    or (result.status != SolverStatus.SAT and result.values)
                    or (query.operation == "check" and result.values)):
                raise ValueError("Worker returned invalid model values/status")
            if query.operation != "check" and result.status == SolverStatus.SAT:
                if (not 1 <= len(result.values) <= query.limit
                        or any(not 0 <= v < (1 << query.expression.width) for v in result.values)):
                    raise ValueError("Worker model does not match BV width/evaluation limit")
            return SolverResult(result.status, result.values, result.reason, result.backend,
                                query.origin, str(folder), process.returncode)
        except (ValueError, KeyError, OSError) as error:
            return SolverResult(SolverStatus.ERROR, reason="Invalid worker response: " + str(error),
                                origin=query.origin, evidence=str(folder), exit_code=process.returncode)
