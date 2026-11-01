"""Target-only private worker used by SubprocessSolverPort."""
import argparse
import ctypes
import faulthandler
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

TARGET = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TARGET))
from p1_runtime import ProbeWriteGuard
from emtaint.solver.port import SolverQuery, SolverResult, SolverStatus


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--folder", type=Path, required=True)
    folder = parser.parse_args().folder.resolve()
    folder.relative_to(TARGET / ".p1-work")
    if not (folder / "cache").is_dir() or (folder / "result.json").exists():
        raise RuntimeError("Require fresh private request directory")
    for key in ("TEMP", "TMP", "TMPDIR"):
        os.environ[key] = str(folder / "cache")
    tempfile.tempdir = str(folder / "cache")
    sys.dont_write_bytecode = True
    if sys.platform == "win32":
        ctypes.windll.kernel32.SetErrorMode(3)
    faulthandler.enable()
    query = SolverQuery.from_dict(json.loads((folder / "request.json").read_text()))
    guard = ProbeWriteGuard([folder]).install()
    print(json.dumps({"checkpoint": "before-native-import", "origin": query.origin}), flush=True)
    try:
        from emtaint.solver.backends.claripy_adapter import ClaripyAdapter
        adapter = ClaripyAdapter()
        print(json.dumps({"checkpoint": "before-solve"}), flush=True)
        result = adapter.solve(query)
    except BaseException as error:
        traceback.print_exc()
        result = SolverResult(SolverStatus.ERROR, reason=type(error).__name__ + ": " + str(error), origin=query.origin)
    finally:
        if guard.violations:
            result = SolverResult(SolverStatus.ERROR, reason="File isolation violation: " + repr(guard.violations), origin=query.origin)
        with (folder / "result.json").open("x", encoding="utf-8") as stream:
            json.dump(result.to_dict(), stream, indent=2)
        guard.restore()
    print(json.dumps(result.to_dict()), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
