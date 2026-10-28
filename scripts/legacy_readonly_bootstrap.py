"""Python 3.7-compatible loader instrumentation; copied into each physical RunRoot."""
import argparse
import builtins
import ctypes
import functools
import hashlib
import importlib
import inspect
import io
import json
import os
from pathlib import Path
import runpy
import sys
import time


class ForbiddenMutation(BaseException):
    """Do not let third-party 'except IOError' hide a denied write."""


class WriteGuard:
    """Python-level write guard, supplemented by full legacy-tree verification.

    This is not a sandbox for arbitrary native code. No ACL or legacy file changes.
    """
    def __init__(self, roots):
        self.roots = [Path(root).resolve() for root in roots]
        self.violations = []
        self.saved = []
        self.file_descriptors = {}

    def check(self, path, operation):
        if isinstance(path, int):
            if path in (0, 1, 2) or path in self.file_descriptors:
                return
            resolved = "untracked file descriptor %d" % path
        else:
            resolved = Path(os.fsdecode(path)).resolve()
            for root in self.roots:
                try:
                    resolved.relative_to(root)
                    return
                except ValueError:
                    pass
        self.violations.append({"operation": operation, "path": str(resolved)})
        raise ForbiddenMutation("Denied %s outside RunRoot/archive: %s" % (operation, resolved))

    def replace(self, obj, name, value):
        self.saved.append((obj, name, getattr(obj, name)))
        setattr(obj, name, value)

    def install(self):
        for owner in (builtins, io):
            original = owner.open

            def guarded_open(file, *args, _original=original, **kwargs):
                mode = args[0] if args else kwargs.get("mode", "r")
                if any(flag in mode for flag in "wax+"):
                    self.check(file, "open:" + mode)
                return _original(file, *args, **kwargs)

            self.replace(owner, "open", guarded_open)
        original_os_open = os.open

        def guarded_os_open(path, flags, *args, **kwargs):
            writes = flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)
            if writes:
                self.check(path, "os.open")
            fd = original_os_open(path, flags, *args, **kwargs)
            if writes:
                self.file_descriptors[fd] = str(path)
            return fd

        self.replace(os, "open", guarded_os_open)
        original_close = os.close

        def guarded_close(fd):
            try:
                return original_close(fd)
            finally:
                self.file_descriptors.pop(fd, None)

        self.replace(os, "close", guarded_close)
        for name in ("remove", "unlink", "mkdir", "rmdir", "chmod", "utime", "truncate"):
            if not hasattr(os, name):
                continue
            original = getattr(os, name)

            def guarded_mutation(path, *args, _original=original, _name=name, **kwargs):
                self.check(path, "os." + _name)
                return _original(path, *args, **kwargs)

            self.replace(os, name, guarded_mutation)
        for name in ("rename", "replace", "link", "symlink"):
            original = getattr(os, name)

            def guarded_move(source, destination, *args, _original=original, _name=name, **kwargs):
                self.check(source, "os." + _name + ":source")
                self.check(destination, "os." + _name + ":destination")
                return _original(source, destination, *args, **kwargs)

            self.replace(os, name, guarded_move)
        return self

    def restore(self):
        for owner, name, original in reversed(self.saved):
            setattr(owner, name, original)
        self.saved = []


def ply_options(kwargs, cache, mode):
    if mode not in ("redirect", "disabled"):
        raise ValueError("Unknown PLY isolation mode")
    options = dict(kwargs)
    options["outputdir"] = str(cache)
    options["debugfile"] = str(cache / "parser.out")
    if mode == "disabled":
        options["write_tables"] = False
    return options


def explicit_ply_arguments(function, args, kwargs, lexer=False):
    options = dict(inspect.signature(function).bind_partial(*args, **kwargs).arguments)
    if options.get("module") is None and not (lexer and options.get("object") is not None):
        raise RuntimeError("Unvalidated implicit PLY invocation")
    return options


def install_ply_isolation(cache, mode):
    # Importing these definitions does not construct a parser. Guard is already active.
    from pycparser.ply import yacc, lex
    calls = []
    original_yacc = yacc.yacc
    original_lex = lex.lex

    @functools.wraps(original_yacc)
    def isolated_yacc(*args, **kwargs):
        options = ply_options(explicit_ply_arguments(original_yacc, args, kwargs), cache, mode)
        calls.append({"kind": "yacc", "start": options.get("start"),
                      "optimize": options.get("optimize", False),
                      "write_tables": options.get("write_tables", True),
                      "outputdir": options["outputdir"]})
        return original_yacc(**options)

    @functools.wraps(original_lex)
    def isolated_lex(*args, **kwargs):
        options = explicit_ply_arguments(original_lex, args, kwargs, lexer=True)
        options["outputdir"] = str(cache)
        calls.append({"kind": "lex", "outputdir": str(cache)})
        return original_lex(**options)

    yacc.yacc, lex.lex = isolated_yacc, isolated_lex
    return calls


def environment_probe():
    modules = {}
    for name in ("angr", "pyvex", "cle", "archinfo", "z3"):
        module = importlib.import_module(name)
        modules[name] = {"version": str(getattr(module, "__version__", None)),
                         "file": module.__file__}
        if name == "z3":
            modules[name]["version"] = module.get_version_string()
    import claripy
    value = claripy.BVS("probe", 32, explicit_name=True)
    return {"python": sys.version, "executable": sys.executable, "prefix": sys.prefix,
            "cache_tag": sys.implementation.cache_tag, "sys_path": sys.path,
            "modules": modules, "claripy": {"module": claripy.__name__,
            "file": claripy.__file__, "type": str(type(value)), "bits": value.size(),
            "Load": hasattr(claripy, "Load"), "Store": hasattr(claripy, "Store"),
            "cache_key": hasattr(value, "cache_key"),
            "recursive_leaf_asts": hasattr(value, "recursive_leaf_asts")}}


def parser_contract():
    import pycparser
    import angr.sim_type as sim_type
    declarations = ["int", "unsigned int", "char *", "int (*)(char *, unsigned int)"]
    types = []
    for declaration in declarations:
        parsed = sim_type.parse_type(declaration)
        types.append({"input": declaration, "class": type(parsed).__name__,
                      "c_repr": parsed.c_repr()})
    parser = pycparser.CParser()
    source = "typedef unsigned int word; struct pair { word n; char *p; }; int emit(struct pair *p);"
    buffer = io.StringIO()
    parser.parse(source).show(buf=buffer, showcoord=False)
    tables = sim_type._type_parser_singleton.cparser
    encoded = json.dumps({"action": tables.action, "goto": tables.goto}, sort_keys=True).encode()
    return {"types": types, "c_ast": buffer.getvalue(),
            "parameter_parser_tables_sha256": hashlib.sha256(encoded).hexdigest()}


def worker_memory():
    if sys.platform != "win32":
        return None
    from ctypes import wintypes

    class Counters(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("PageFaultCount", wintypes.DWORD)] + [
            (name, ctypes.c_size_t) for name in ("PeakWorkingSetSize", "WorkingSetSize",
             "QuotaPeakPagedPoolUsage", "QuotaPagedPoolUsage", "QuotaPeakNonPagedPoolUsage",
             "QuotaNonPagedPoolUsage", "PagefileUsage", "PeakPagefileUsage")]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.POINTER(Counters), wintypes.DWORD]
    psapi.GetProcessMemoryInfo.restype = wintypes.BOOL
    counters = Counters()
    counters.cb = ctypes.sizeof(counters)
    if not psapi.GetProcessMemoryInfo(kernel.GetCurrentProcess(), ctypes.byref(counters), counters.cb):
        raise ctypes.WinError(ctypes.get_last_error())
    return {"pid": os.getpid(), "peak_working_set_bytes": counters.PeakWorkingSetSize,
            "scope": "actual bootstrap/analysis worker; kernel peak; not aggregate process tree"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--archive-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--mode", choices=("redirect", "disabled"), default="disabled")
    parser.add_argument("--action", choices=("probe", "environment", "module", "main"), required=True)
    parser.add_argument("--profile-file", type=Path)
    parser.add_argument("arguments", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    run_root, archive = args.run_root.resolve(), args.archive_root.resolve()
    if Path(__file__).resolve().parent != run_root or Path.cwd().resolve() != run_root:
        raise RuntimeError("Bootstrap must be physically copied into and executed in RunRoot")
    migration = next((p.parent for p in run_root.parents if p.name == "baseline-work"), None)
    if migration is None:
        raise RuntimeError("RunRoot is not inside baseline-work")
    archive.relative_to(migration / "baselines")
    args.report.resolve().relative_to(archive)
    if args.profile_file is not None:
        args.profile_file.resolve().relative_to(archive)
    if args.mode == "redirect" and args.action != "probe":
        raise RuntimeError("Table-writing reference mode is limited to parser validation")
    cache = run_root / ".p0b-cache" / args.report.stem
    cache.mkdir(parents=True, exist_ok=False)
    for name in ("TEMP", "TMP", "TMPDIR"):
        os.environ[name] = str(cache)
    sys.dont_write_bytecode = True
    guard = WriteGuard([run_root, archive]).install()
    report = {"mode": args.mode, "action": args.action, "schema_version": 1,
              "run_root": str(run_root), "archive_root": str(archive)}
    started = time.perf_counter()
    error = None
    try:
        calls = install_ply_isolation(cache, args.mode)
        report["ply_calls"] = calls
        tail = args.arguments
        if tail and tail[0] == "--":
            tail = tail[1:]
        if args.action in ("probe", "environment"):
            value = {"environment": environment_probe()}
            if args.action == "probe":
                value["contract"] = parser_contract()
            print(json.dumps(value), flush=True)
        elif args.action == "module":
            if not tail or tail[0] != "pip":
                raise RuntimeError("Only pip read-only metadata commands are supported")
            if len(tail) < 2 or tail[1] not in ("freeze", "check"):
                raise RuntimeError("Package mutations are prohibited")
            sys.argv = tail
            runpy.run_module("pip", run_name="__main__", alter_sys=True)
        else:
            sys.path.insert(0, str(run_root))
            sys.argv = ["main.py"] + tail
            if args.profile_file is None:
                runpy.run_path("main.py", run_name="__main__")
            else:
                import cProfile
                profiler = cProfile.Profile()
                profiler.enable()
                try:
                    runpy.run_path("main.py", run_name="__main__")
                finally:
                    profiler.disable()
                    profiler.dump_stats(str(args.profile_file))
    except SystemExit as caught:
        if caught.code not in (0, None):
            error = caught
    except BaseException as caught:
        error = caught
    finally:
        report["wall_seconds"] = time.perf_counter() - started
        report["worker_memory"] = worker_memory()
        report["violations"] = guard.violations
        report["cache_files"] = [{"path": p.relative_to(cache).as_posix(),
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in sorted(cache.rglob("*")) if p.is_file()]
        report["ok"] = error is None and not guard.violations
        report["error"] = repr(error) if error is not None else None
        with args.report.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
        guard.restore()
    if error is not None:
        raise error
    if not report["ok"]:
        raise RuntimeError("Bootstrap detected a forbidden write")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
