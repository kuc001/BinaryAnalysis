"""Python CLI with explicit inputs and isolated, append-only phase outputs."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from dataclasses import asdict
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import tempfile
import time
import uuid

from emtaint.debugging import (
    configure_logging,
    function_address_fields,
    log_event,
    progress_heartbeat,
)
from emtaint.frontends.function_store import FunctionStore
from emtaint.frontends.inputs import read_ida_cfg
from emtaint.frontends.program_index import build_program_index
from emtaint.ir.canonical import CIRModule
from emtaint.memory.engine import combine
from emtaint.orchestration.icall_program import recover_icalls


LOGGER = logging.getLogger(__name__)
SOURCE_SCRIPTS = (
    "p1_runtime.py",
    "legacy_readonly_bootstrap.py",
    "p7_legacy_reference.py",
    "legacy_baseline.py",
    "baseline_inventory.py",
    "compare_baseline.py",
)


def write(path: Path, value: object) -> None:
    """Create one JSON receipt without overwriting an existing artifact.

    Args:
        path: Destination file. Its parent must already exist.
        value: JSON-compatible value. Unsupported leaves are converted to text.
    """

    with path.open("x", encoding="utf8") as stream:
        json.dump(value, stream, indent=2, default=str)


def source_manifest(root: Path) -> dict[str, str]:
    """Hash source files that define one CLI analysis execution.

    Args:
        root: Absolute BinaryAnalysis repository root.

    Returns:
        Mapping from repository-relative POSIX path to SHA256 digest.
    """

    paths = list((root / "emtaint").rglob("*.py"))
    paths.append(root / "main.py")
    paths.extend(root / "scripts" / name for name in SOURCE_SCRIPTS)
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(paths)
    }


def process_metadata() -> dict[str, object]:
    """Capture pinned package versions and whole-process memory accounting."""

    import importlib.metadata

    import psutil

    memory = psutil.Process().memory_info()
    packages = {
        name: importlib.metadata.version(name)
        for name in (
            "angr",
            "claripy",
            "pyvex",
            "cle",
            "archinfo",
            "z3-solver",
            "psutil",
        )
    }
    return {
        "packages": packages,
        "process_peak_rss_bytes": getattr(memory, "peak_wset", None),
        "process_rss_at_receipt_bytes": memory.rss,
        "rss_scope": (
            "Whole CLI process, including frontend and analysis; "
            "peak_wset is the Windows process high-water mark"
        ),
    }


def run_icall(
    args: argparse.Namespace,
    store: FunctionStore,
    folder: Path,
) -> dict[str, object]:
    """Run the bounded iCall phase and write append-only evidence artifacts.

    Args:
        args: Validated CLI arguments for an ``-i`` execution.
        store: Immutable per-function CIR acquisition reader.
        folder: Newly created output directory beneath ``.p7-work``.

    Returns:
        The iCall phase manifest also written to ``icall.json``.
    """

    metadata = Path(args.ida_data)
    block_info = json.loads(
        (metadata / "httpd_block_info.json").read_text(encoding="utf8")
    )
    sites = sorted(
        (int(function, 16), row[0])
        for function, blocks in block_info.items()
        for rows in blocks.values()
        for row in rows
        if row[-1] == "iCall"
    )
    # for function, site in sites:
    #     print(f"iCall site: {hex(function)} -> {hex(site)}")
    log_event(
        LOGGER,
        "icall.sites.discovered",
        level=logging.INFO,
        sites=len(sites),
        functions=len({function for function, _ in sites}),
        metadata=str(metadata.resolve()),
    )

    # This dependency plan was independently validated for the approved P6
    # target. It selects bodies to compute and is not a Golden target list.
    approved_binary = "334907567ea77265a6c7c67398781adef01e1dbc22fc1f0bbece4c38e564a787"
    if store.report["binary_sha256"] != approved_binary:
        raise ValueError("No validated iCall dependency policy for this binary")

    selected = {function for function, _ in sites}
    selected.update({0x1EA0C, 0x1E9AC, 0x1E8A8, 0x23DC4, 0x29590, 0x2E9B4})
    modules = []
    cfgs = []
    body_hashes = {}
    for address in sorted(selected):
        log_event(
            LOGGER,
            "icall.function.loading",
            **function_address_fields(
                address - store.base,
                store.base,
                legacy_field="va",
            ),
            loaded=len(modules),
            total=len(selected),
        )
        function_module, cfg, digest = store.load(address)
        modules.append(function_module)
        cfgs.append(cfg)
        body_hashes[function_module.functions[0].function_id] = digest
        log_event(
            LOGGER,
            "icall.function.loaded",
            **function_address_fields(
                address - store.base,
                store.base,
                legacy_field="va",
            ),
            cir_sha256=digest,
            blocks=len(cfg.nodes),
            loaded=len(modules),
            total=len(selected),
        )

    first = modules[0]
    module = CIRModule(
        first.producer,
        first.architecture,
        first.endian,
        first.binary_sha256,
        tuple(function for item in modules for function in item.functions),
        tuple(origin for item in modules for origin in item.origin_map),
        first.capabilities,
        combine(item.assessment for item in modules),
    )
    specifications = read_ida_cfg(metadata / "httpd_cfg.json")
    log_event(
        LOGGER,
        "icall.index.building",
        level=logging.INFO,
        functions=len(module.functions),
        cfgs=len(cfgs),
        ida_functions=len(specifications),
        input_sites=len(sites),
    )
    index = build_program_index(
        module,
        specifications,
        store.base,
        input_sites=sites,
        native_cfgs=cfgs,
    )
    log_event(
        LOGGER,
        "icall.recovery.started",
        level=logging.INFO,
        program_functions=len(index.program.functions),
        callsites=len(index.program.callsites),
        cg_edges=len(index.cg.edges),
    )
    runtime, result, invocations = recover_icalls(
        module=module,
        index=index,
        segments=store.segments,
        sections=store.loader["sections"],
        input_sites=sites,
        body_hashes=body_hashes,
    )
    log_event(
        LOGGER,
        "icall.recovery.completed",
        level=logging.INFO,
        rounds=result.rounds,
        analyzed_functions=len(result.results),
        pending_functions=len(result.pending),
        invocations=len(invocations),
        invalidation_events=len(runtime.events),
    )

    targets: dict[str, dict[str, list[int]]] = {}
    facts = []
    coverage = []
    for function_id, outcome in result.results:
        function_address = function_id.rva + store.base
        log_event(
            LOGGER,
            "icall.function.result",
            **function_address_fields(
                function_id.rva,
                store.base,
                legacy_field="va",
            ),
            sites=len(outcome.sites),
            target_facts=len(outcome.targets),
            pending=len(outcome.pending),
        )
        for row in outcome.sites:
            coverage.append(
                {
                    "function": function_address,
                    **row.to_legacy_dict(),
                }
            )
        for fact in outcome.targets:
            site_address = fact.site.point.instruction_rva + store.base
            targets.setdefault(str(function_address), {})[str(site_address)] = list(
                fact.targets
            )
            facts.append(
                {
                    "function": function_address,
                    "site": site_address,
                    "targets": fact.targets,
                    "certainty": fact.certainty,
                    "exhaustive": fact.exhaustive,
                    "memory_version": asdict(fact.memory),
                    "origin": fact.origin,
                    "assessment": asdict(fact.assessment),
                }
            )
            log_event(
                LOGGER,
                "icall.site.resolved",
                **function_address_fields(
                    function_id.rva,
                    store.base,
                    legacy_field="va",
                ),
                site=hex(site_address),
                site_rva=hex(fact.site.point.instruction_rva),
                site_va=hex(site_address),
                targets=len(fact.targets),
                certainty=fact.certainty,
                exhaustive=fact.exhaustive,
            )

    logical_edges = {
        (
            ("internal", edge.site.function.rva + store.base),
            ("internal", edge.target.rva + store.base),
        )
        for edge in runtime.session.cg.edges
        if edge.target is not None
    }
    logical_edges.update(
        (("internal", function.rva + store.base), ("external", name))
        for function, _, name in index.external_calls
    )
    pending = [
        {
            "function": function.rva + store.base,
            "pending": list(outcome.pending),
        }
        for function, outcome in result.results
        if outcome.pending
    ]
    target_entries = sum(
        len(values)
        for function_sites in targets.values()
        for values in function_sites.values()
    )
    status = "incomplete" if pending or result.pending else "candidate_fixed_point"
    manifest = {
        "phase": "icall",
        "engine": "python",
        "memory_engine": "apg",
        "binary_sha256": module.binary_sha256,
        "acquisition": str(store.folder.resolve()),
        "metadata": str(metadata.resolve()),
        "status": status,
        "input_sites": len(sites),
        "observed_sites": len(coverage),
        "target_entries": target_entries,
        "logical_cg_edges": len(logical_edges),
        "rounds": result.rounds,
        "function_pending": pending,
        "graph_pending": [function.rva + store.base for function in result.pending],
        "selected_bodies": sorted(selected),
        "certainty": "MAY; runtime memory/guard remainder retained",
        "gate_a": "NOT_EVALUATED",
        "plt_sha256": store.plt_sha256,
    }
    artifacts = (
        ("icall-targets", targets),
        ("target-facts", facts),
        ("site-coverage", coverage),
        ("cg-logical-edges", sorted(logical_edges)),
        ("invalidation-events", runtime.events),
        ("invocations", invocations),
        ("cir-transformations", store.transformations),
        (
            "plt-mapping",
            {
                "binary_sha256": module.binary_sha256,
                "plt": store.plt,
                "sha256": store.plt_sha256,
            },
        ),
        ("icall", manifest),
    )
    log_event(
        LOGGER,
        "icall.artifacts.writing",
        level=logging.INFO,
        artifacts=len(artifacts),
        observed_sites=len(coverage),
        target_entries=target_entries,
        logical_cg_edges=len(logical_edges),
        status=status,
    )
    for name, value in artifacts:
        path = folder / f"{name}.json"
        write(path, value)
        log_event(
            LOGGER,
            "icall.artifact.written",
            name=name,
            path=str(path),
            bytes=path.stat().st_size,
        )
    return manifest


def build_parser() -> argparse.ArgumentParser:
    """Build the public CLI parser without executing an analysis."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("-f", "--binary_file", required=True)
    parser.add_argument("-n", "--firmware_name")
    parser.add_argument("-v", "--firmware_version")

    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("-i", "--icall_check", action="store_true")
    modes.add_argument("-t", "--taint_check", action="store_true")
    modes.add_argument("-a", "--alias-check", action="store_true")

    parser.add_argument("--ida-data")
    parser.add_argument("--acquisition")
    parser.add_argument("--output", required=True)
    parser.add_argument("--debug-ida-image-base", type=lambda value: int(value, 0),
                        help="Explicit IDA database image base for debug RVA-to-VA display")
    parser.add_argument("--debug-runtime-base", type=lambda value: int(value, 0),
                        help="Optional runtime module base, independent of IDA database base")
    parser.add_argument("--function", help="Alias query function name or absolute address")
    parser.add_argument("--site", type=lambda value: int(value, 0), help="Absolute callsite address")
    parser.add_argument("--left", help="Binary value locator, e.g. arg:0")
    parser.add_argument("--right", help="Binary value locator, e.g. arg:1")
    parser.add_argument("--discover-alias-calls", action="store_true")
    parser.add_argument("--observe-call", action="append", default=[], help="Pure binary query function symbol")
    parser.add_argument("--engine", choices=("python",), default="python")
    parser.add_argument(
        "--memory-engine",
        choices=("apg", "legacy"),
        default="apg",
    )
    parser.add_argument(
        "--legacy-plan",
        help="Separately approved physical-copy plan for the real old Python reference",
    )
    parser.add_argument(
        "--legacy-resume-prepared",
        action="store_true",
        help=(
            "Verify and resume an approved physical copy stopped before "
            "parser/main execution"
        ),
    )
    parser.add_argument(
        "--function-seconds",
        type=int,
        default=120,
        help="Per-function demand deadline; exhausted frontier stays incomplete",
    )
    parser.add_argument(
        "--taint-rounds",
        type=int,
        default=15,
        help="Summary fixed-point round budget",
    )
    parser.add_argument(
        "--taint-functions",
        nargs="+",
        type=lambda value: int(value, 0),
        help="Diagnostic function subset; always reported as incomplete program coverage",
    )
    parser.add_argument(
        "--log-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        default="WARNING",
        help="Opt-in diagnostic verbosity; WARNING preserves the quiet default",
    )
    parser.add_argument(
        "--log-file",
        help="New log filename inside --output; existing files are never overwritten",
    )
    parser.add_argument(
        "--log-format",
        choices=("text", "jsonl"),
        default="text",
        help="Diagnostic encoding; jsonl writes an indented JSON event array",
    )
    parser.add_argument(
        "--log-console",
        action="store_true",
        help="Also stream human-readable progress while retaining the log file",
    )
    parser.add_argument(
        "--log-console-level",
        choices=("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"),
        help=(
            "Optional console threshold independent from --log-level; "
            "the file retains the full requested detail"
        ),
    )
    return parser


def validate_arguments(args: argparse.Namespace) -> None:
    """Reject invalid mode, budget, backend, and diagnostic combinations."""

    for option_name in ("debug_ida_image_base", "debug_runtime_base"):
        option_value = getattr(args, option_name, None)
        if option_value is not None and option_value < 0:
            raise ValueError("--" + option_name.replace("_", "-") + " must be non-negative")

    if args.alias_check:
        if args.discover_alias_calls:
            if not args.observe_call or any(
                    value is not None for value in
                    (args.function, args.site, args.left, args.right)):
                raise ValueError("Alias scan requires --observe-call and no manual locator")
        elif any(value is None for value in
                 (args.function, args.site, args.left, args.right)):
            raise ValueError("Manual alias query requires function, site, left and right")
        if args.memory_engine != "apg" or args.legacy_plan or args.legacy_resume_prepared:
            raise ValueError("Alias mode uses the shared native memory engine")
        return
    if not all((args.firmware_name, args.firmware_version, args.ida_data, args.acquisition)):
        raise ValueError("-i/-t require firmware identity, IDA data and acquisition")
    if args.function_seconds < 1 or not 1 <= args.taint_rounds <= 15:
        raise ValueError("Positive function deadline and 1..15 taint rounds required")
    if args.icall_check and args.taint_functions:
        raise ValueError("--taint-functions is a -t diagnostic option")
    if (args.memory_engine == "legacy") != bool(args.legacy_plan):
        raise ValueError(
            "--memory-engine legacy requires --legacy-plan, which is exclusive "
            "to that backend"
        )
    if args.legacy_resume_prepared and (
        args.memory_engine != "legacy" or not args.icall_check
    ):
        raise ValueError("Prepared resume requires legacy -i")
    if args.memory_engine == "legacy" and args.taint_functions:
        raise ValueError("Legacy reference does not support APG diagnostic subsets")


def prepare_output(args: argparse.Namespace, root: Path) -> Path:
    """Validate the write boundary and prepare the requested phase directory."""

    folder = Path(args.output).resolve()
    folder.relative_to(root)
    folder.relative_to(root / ".p7-work")
    if args.icall_check:
        if args.legacy_resume_prepared:
            if not folder.is_dir() or (folder / "icall.json").exists():
                raise ValueError("No unstarted prepared legacy output directory")
        else:
            folder.mkdir(exist_ok=False)
    elif not folder.is_dir() or not (folder / "icall.json").is_file():
        raise ValueError("-t requires the same completed -i output directory")
    return folder


def main(argv: Sequence[str] | None = None) -> int:
    """Validate CLI inputs, execute one isolated phase, and return its status.

    Args:
        argv: Optional arguments without the executable name. ``None`` delegates
            to ``sys.argv`` through ``argparse``.

    Returns:
        ``0`` for a completed phase and ``2`` for explicit incomplete output or
        write-guard violations. Input/runtime errors are raised after a receipt.
    """

    args = build_parser().parse_args(argv)
    validate_arguments(args)
    if args.alias_check:
        from emtaint.analysis.aliasing.cli_runner import run_alias_cli

        return run_alias_cli(args)
    root = Path(__file__).resolve().parents[1]
    folder = prepare_output(args, root)

    if args.memory_engine == "legacy":
        sys.path.insert(0, str(root / "scripts"))
        from p7_legacy_reference import execute

        return execute(args, folder)

    cache_name = "cache-i" if args.icall_check else f"cache-t-{uuid.uuid4().hex[:8]}"
    cache = folder / cache_name
    cache.mkdir(exist_ok=False)
    for key in ("TEMP", "TMP", "TMPDIR"):
        os.environ[key] = str(cache)
    tempfile.tempdir = str(cache)
    sys.dont_write_bytecode = True

    sys.path.insert(0, str(root / "scripts"))
    from p1_runtime import ProbeWriteGuard

    guard = ProbeWriteGuard([folder]).install()
    started = time.monotonic()
    try:
        log_path = None
        if args.log_file:
            if Path(args.log_file).name != args.log_file:
                raise ValueError("--log-file must be a filename, not a path")
            log_path = folder / args.log_file
        configure_logging(
            args.log_level,
            log_path,
            json_lines=args.log_format == "jsonl",
            console=args.log_console,
            console_level=args.log_console_level,
        )
        log_event(
            LOGGER,
            "cli.started",
            level=logging.INFO,
            mode="icall" if args.icall_check else "taint",
            output=str(folder),
            binary=str(Path(args.binary_file).resolve()),
            memory_engine=args.memory_engine,
            selected_functions=args.taint_functions,
        )

        log_event(
            LOGGER,
            "cli.source_manifest.started",
            source_root=str(root / "emtaint"),
        )
        sources = source_manifest(root)
        source_receipt = cache / "source-start.json"
        write(source_receipt, sources)
        log_event(
            LOGGER,
            "cli.source_manifest.completed",
            files=len(sources),
            receipt=str(source_receipt),
        )

        acquisition = str(Path(args.acquisition).resolve())
        log_event(
            LOGGER,
            "cli.acquisition.started",
            level=logging.INFO,
            acquisition=acquisition,
        )
        with progress_heartbeat(
            LOGGER,
            "cli.acquisition.heartbeat",
            acquisition=acquisition,
        ):
            store = FunctionStore(args.acquisition, binary=args.binary_file)
        log_event(
            LOGGER,
            "cli.acquisition.completed",
            level=logging.INFO,
            base=hex(store.base),
            binary_sha256=store.report["binary_sha256"],
            metadata_sha256=store.report["metadata_sha256"],
            plt_sha256=store.plt_sha256,
        )

        log_event(LOGGER, "cli.inputs.validating", level=logging.INFO)
        binary_sha = hashlib.sha256(Path(args.binary_file).read_bytes()).hexdigest()
        metadata_path = Path(args.ida_data) / "httpd_cfg.json"
        metadata_sha = hashlib.sha256(metadata_path.read_bytes()).hexdigest()
        if binary_sha != store.report["binary_sha256"]:
            raise ValueError("Binary/acquisition hash mismatch")
        if metadata_sha != store.report["metadata_sha256"]:
            raise ValueError("IDA CFG/acquisition hash mismatch")
        log_event(
            LOGGER,
            "cli.inputs.validated",
            level=logging.INFO,
            binary_sha256=binary_sha,
            metadata_sha256=metadata_sha,
        )

        if args.icall_check:
            manifest = run_icall(args, store, folder)
            command_name = "icall-command.json"
        else:
            from emtaint.orchestration.taint_program import run_taint

            manifest = run_taint(args, store, folder)
            command_name = f"taint-command-{uuid.uuid4().hex[:8]}.json"

        command_receipt = {
            "argv": sys.argv if argv is None else argv,
            "executable": sys.executable,
            "python": sys.version,
            "source_unchanged_during_run": sources == source_manifest(root),
            "source_manifest": str(source_receipt),
            "wall_seconds": time.monotonic() - started,
            "violations": guard.violations,
            **process_metadata(),
        }
        write(folder / command_name, command_receipt)
        log_event(
            LOGGER,
            "cli.completed",
            level=logging.INFO,
            status=manifest["status"],
            wall_seconds=time.monotonic() - started,
            write_violations=len(guard.violations),
        )
    except BaseException as error:
        log_event(
            LOGGER,
            "cli.failed",
            level=logging.ERROR,
            error=error,
            error_type=type(error).__name__,
            error_message=str(error),
            wall_seconds=time.monotonic() - started,
        )
        write(
            cache / "command-error.json",
            {
                "argv": sys.argv if argv is None else argv,
                "executable": sys.executable,
                "status": "failed",
                "error": f"{type(error).__name__}: {error}",
                "wall_seconds": time.monotonic() - started,
                "violations": guard.violations,
                **process_metadata(),
            },
        )
        raise
    finally:
        guard.restore()

    print(json.dumps(manifest, default=str), flush=True)
    if guard.violations or manifest["status"] in ("failed", "incomplete"):
        return 2
    return 0
