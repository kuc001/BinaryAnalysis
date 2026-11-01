"""Python 3.7-compatible, process-isolated native API contracts. No legacy analysis."""
import argparse
import ctypes
import faulthandler
import hashlib
import importlib
import json
import os
from pathlib import Path
import sys
import tempfile
import traceback

from legacy_readonly_bootstrap import WriteGuard, install_ply_isolation
from p1_runtime import ProbeWriteGuard


def emit(kind, value):
    print(json.dumps({"kind": kind, "value": value}, sort_keys=True), flush=True)


def loaded_libraries():
    if sys.platform != "win32":
        return []
    from ctypes import wintypes
    kernel = ctypes.WinDLL("kernel32")
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    psapi = ctypes.WinDLL("psapi")
    psapi.EnumProcessModules.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.HMODULE),
                                        wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    psapi.GetModuleFileNameExW.argtypes = [wintypes.HANDLE, wintypes.HMODULE,
                                         wintypes.LPWSTR, wintypes.DWORD]
    modules = (wintypes.HMODULE * 2048)()
    needed = wintypes.DWORD()
    process = kernel.GetCurrentProcess()
    if not psapi.EnumProcessModules(process, modules, ctypes.sizeof(modules), ctypes.byref(needed)):
        raise ctypes.WinError()
    result = []
    for module in modules[:min(2048, needed.value // ctypes.sizeof(wintypes.HMODULE))]:
        buf = ctypes.create_unicode_buffer(32768)
        if psapi.GetModuleFileNameExW(process, module, buf, len(buf)):
            if any(word in buf.value.lower() for word in ("z3", "rustylib", "libpyvex", "python3")):
                result.append(buf.value)
    return result


def expressions(c):
    x = c.BVS("p1_x", 32, explicit_name=True)
    x2 = c.BVS("p1_x", 32, explicit_name=True)
    y = c.BVS("p1_y", 32, explicit_name=True)
    expr = x + c.BVV(8, 32)
    changed = expr.replace(x, y) if hasattr(expr, "replace") else c.replace(expr, x, y)
    folded = c.simplify(c.BVV(0xffffffff, 32) + c.BVV(2, 32))
    values = {
        "extract": c.Extract(15, 8, c.BVV(0x12345678, 32)),
        "concat": c.Concat(c.BVV(0x12, 8), c.BVV(0x34, 8)),
        "zero_ext": c.ZeroExt(8, c.BVV(0x80, 8)),
        "sign_ext": c.SignExt(8, c.BVV(0x80, 8)),
        "ite": c.If(c.BoolV(True), c.BVV(7, 32), c.BVV(9, 32)),
        "wrap": folded,
    }
    result = {"module": c.__name__, "ast_type": str(type(x)), "bits": x.size(),
        "op": x.op, "args": list(map(str, x.args)), "variables": sorted(x.variables),
        "same_hash": hash(x) == hash(x2), "annotations_type": type(x.annotations).__name__,
        "replacement_variables": sorted(changed.variables),
        "api": {n: hasattr(x, n) for n in ("cache_key", "recursive_children_asts",
                                          "recursive_leaf_asts", "replace", "annotations")},
        "module_api": {n: hasattr(c, n) for n in ("Load", "Store", "operations")},
        "concrete": {k: {"op": v.op, "args": list(map(str, v.args)), "bits": v.size()}
                     for k, v in values.items()}}
    annotation = c.SimplificationAvoidanceAnnotation()
    annotated = x.annotate(annotation)
    result["annotation"] = {"count": len(annotated.annotations),
                            "type": type(annotated.annotations[0]).__name__}
    try:
        c.Extract(40, 33, x)
        result["invalid_extract"] = "accepted"
    except Exception as error:
        result["invalid_extract"] = type(error).__name__
    source = Path(__file__).resolve().parents[1] / "emtaint/solver/backends/ast_tools.py"
    spec = importlib.util.spec_from_file_location("p1_ast_tools", str(source))
    tools = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tools)
    repeated = c.Concat(x, x)
    result["adapter_contract"] = {
        "key": tools.structural_key(c, repeated), "export": tools.export(c, repeated),
        "children_occurrences": len(list(tools.children(c, repeated))),
        "children_unique": len(list(tools.children(c, repeated, unique=True))),
        "leaf_names": [a.args[0] for a in tools.leaves(c, repeated)],
        "replaced": tools.export(c, tools.replace(c, repeated, x, y)),
    }
    try:
        tools.replace(c, repeated, x, c.BVS("narrow", 16, explicit_name=True))
        result["adapter_contract"]["mismatched_replace"] = "accepted"
    except ValueError:
        result["adapter_contract"]["mismatched_replace"] = "rejected"
    return result


def run_case(case, environment):
    if case == "z3-direct":
        import z3
        emit("checkpoint", {"step": "z3-import", "version": z3.get_version_string(),
                            "libraries": loaded_libraries()})
        x = z3.BitVec("p1_x", 32)
        s = z3.Solver()
        s.set(timeout=1000)
        s.add(x == 7)
        emit("checkpoint", {"step": "before-z3-check"})
        status = s.check()
        return {"status": str(status), "value": s.model().eval(x).as_long() if status == z3.sat else None}
    if case == "z3-preload":
        import z3
        emit("checkpoint", {"step": "preloaded-z3", "version": z3.get_version_string()})
    import angr
    import claripy as c
    emit("checkpoint", {"step": "angr-import", "version": str(angr.__version__),
                        "libraries": loaded_libraries()})
    if case == "expressions":
        return expressions(c)
    if case == "backend-status":
        import z3
        output = {}
        for name, status, reason in (("sat", z3.sat, ""), ("unsat", z3.unsat, ""),
                                     ("unknown", z3.unknown, "incomplete"),
                                     ("timeout", z3.unknown, "timeout")):
            class FixtureSolver:
                calls = 0
                def check(self, *args):
                    self.calls += 1
                    return status
                def reason_unknown(self):
                    return reason
            fixture = FixtureSolver()
            try:
                value = c.backends.z3._satisfiable(solver=fixture)
                item = {"boolean": value}
            except Exception as error:
                item = {"error_type": type(error).__name__, "error": str(error)}
            output[name] = dict(item, raw_check_calls=fixture.calls)
        return {"kind": "fault injection into real backend, not natural UNKNOWN", "cases": output}
    if case == "memory-markers":
        if not hasattr(c, "Load"):
            return {"status": "UNSUPPORTED", "reason": "No custom Load/Store API"}
        p = c.BVS("p1_pointer", 32, explicit_name=True)
        results = {}
        for op in ("Load", "Store"):
            node = getattr(c, op)(p, 16)
            result = {"op": node.op, "args_count": len(node.args), "address_bits": node.args[0].size(),
                      "bits": node.size()}
            try:
                s = c.Solver(timeout=1000)
                s.add(node == c.BVV(7, 16))
                result["sat"] = s.satisfiable()
            except Exception as error:
                result["error_type"] = type(error).__name__
                result["error"] = str(error)
            results[op] = result
        return results
    if case == "timeout":
        import z3
        original_check = z3.Solver.check
        raw_checks = []
        def observed_check(solver, *arguments):
            status = original_check(solver, *arguments)
            raw_checks.append({"status": str(status),
                               "reason": solver.reason_unknown() if status == z3.unknown else None})
            return status
        z3.Solver.check = observed_check
        try:
            # Pigeonhole: 32 different values must fit into 31 choices.
            terms = [c.BVS("pigeon_%d" % i, 5, explicit_name=True) for i in range(32)]
            constraints = [c.ULT(t, c.BVV(31, 5)) for t in terms]
            constraints += [terms[i] != terms[j] for i in range(32) for j in range(i)]
            s = c.Solver(timeout=1)
            s.add(constraints)
            emit("checkpoint", {"step": "before-timeout-query", "timeout_ms": 1})
            try:
                frontend = {"frontend_boolean": s.satisfiable()}
            except Exception as error:
                frontend = {"error_type": type(error).__name__, "error": str(error)}
            return dict(frontend, raw_checks=raw_checks, timeout_ms=1)
        finally:
            z3.Solver.check = original_check
    x = c.BVS("p1_x", 32, explicit_name=True)
    emit("checkpoint", {"step": "before-solver-construct"})
    s = c.Solver(timeout=1000)
    emit("checkpoint", {"step": "before-add", "timeout": s.timeout})
    s.add(x == c.BVV(7, 32))
    if case == "unsat":
        s.add(x == c.BVV(8, 32))
    emit("checkpoint", {"step": "before-satisfiable", "libraries": loaded_libraries()})
    sat = s.satisfiable()
    result = {"sat": sat, "timeout": s.timeout}
    if case != "unsat" and sat:
        emit("checkpoint", {"step": "before-eval"})
        values = s.eval(x, 2)
        result.update({"values": list(values), "eval_type": type(values).__name__,
                       "min": s.min(x), "max": s.max(x)})
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--environment", choices=("legacy", "target"), required=True)
    parser.add_argument("--case", required=True)
    parser.add_argument("--cache", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    target = Path(__file__).resolve().parents[1]
    cache = args.cache.resolve()
    report_path = args.report.resolve()
    cache.relative_to(target / ".p1-work")
    report_path.relative_to(target / ".p1-work")
    if not cache.is_dir() or report_path.exists():
        raise RuntimeError("Require fresh existing private cache and absent report")
    sys.dont_write_bytecode = True
    for key in ("TEMP", "TMP", "TMPDIR"):
        os.environ[key] = str(cache)
    tempfile.tempdir = str(cache)
    if sys.platform == "win32":
        ctypes.windll.kernel32.SetErrorMode(3)
    faulthandler.enable()
    guard = ProbeWriteGuard([cache, report_path.parent]).install()
    report = {"python": sys.version, "executable": sys.executable,
              "case": args.case, "environment": args.environment}
    error = None
    try:
        if args.environment == "legacy":
            report["ply_calls"] = install_ply_isolation(cache, "disabled")
        report["result"] = run_case(args.case, args.environment)
    except BaseException as caught:
        error = caught
        report["error_type"] = type(caught).__name__
        report["error"] = str(caught)
        traceback.print_exc()
    finally:
        report["violations"] = guard.violations
        report["ok"] = error is None and not guard.violations
        with report_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
        guard.restore()
    emit("result", report)
    return 0 if report["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
