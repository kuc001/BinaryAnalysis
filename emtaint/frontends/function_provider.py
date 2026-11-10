"""Live and replay function providers for bounded single-site analysis."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import importlib.metadata
import json
from pathlib import Path
from typing import Any

from emtaint.analysis.controlflow.local_constants import local_constant_edges
from emtaint.frontends.function_store import FunctionStore
from emtaint.frontends.inputs import FunctionInput, InputError, read_ida_cfg
from emtaint.frontends.loader_image import relocated_image
from emtaint.graph import ControlFlowGraph
from emtaint.ir.canonical import CIRModule, CallEffect, IndirectTarget
from emtaint.ir.canonical.wire import dumps
from emtaint.memory.engine import combine
from emtaint.orchestration.icall_policy import dependency_policy


@dataclass(frozen=True)
class ResolvedICall:
    """Frontend-owned identity for one requested indirect call."""

    caller: int
    site: int
    block: int
    mode: str
    frontend: str


def _safe_version(name: str) -> str | None:
    try:
        return importlib.metadata.version(name)
    except importlib.metadata.PackageNotFoundError:
        return None


def _metadata_paths(binary: Path, ida_data: Path) -> tuple[Path, Path]:
    cfg = ida_data / f"{binary.name}_cfg.json"
    blocks = ida_data / f"{binary.name}_block_info.json"
    if not cfg.is_file():
        raise InputError(f"Missing IDA CFG metadata: {cfg}")
    return cfg, blocks


def _covering_specifications(
    specifications: tuple[FunctionInput, ...],
    site: int,
) -> tuple[tuple[FunctionInput, int], ...]:
    return tuple(
        (specification, block.start)
        for specification in specifications
        for block in specification.blocks
        if not block.boundary and block.start <= site < block.end
    )


def resolve_ida_icall(
    binary: Path,
    ida_data: Path,
    site: int,
) -> tuple[ResolvedICall, tuple[FunctionInput, ...], Path, Path | None]:
    """Resolve a requested site from optional IDA annotations and CFG bounds."""

    cfg_path, block_path = _metadata_paths(binary, ida_data)
    specifications = read_ida_cfg(cfg_path)
    annotated: list[tuple[int, int]] = []
    if block_path.is_file():
        document = json.loads(block_path.read_text(encoding="utf8"))
        for function, blocks in document.items():
            for rows in blocks.values():
                for row in rows:
                    if row[-1] == "iCall" and row[0] == site:
                        annotated.append((int(function, 16), row[0]))
        if len(annotated) > 1:
            raise InputError(
                f"IDA iCall address {hex(site)} maps to multiple callers: "
                + ", ".join(hex(caller) for caller, _ in annotated)
            )
    covering = _covering_specifications(specifications, site)
    if annotated:
        caller = annotated[0][0]
        covering = tuple(row for row in covering if row[0].address == caller)
    if len(covering) != 1:
        callers = sorted({row[0].address for row in covering})
        detail = "not recovered" if not callers else ", ".join(map(hex, callers))
        raise InputError(
            f"Requested address {hex(site)} does not have one IDA caller: {detail}"
        )
    specification, block = covering[0]
    return (
        ResolvedICall(specification.address, site, block, "default", "ida-metadata-vex"),
        specifications,
        cfg_path,
        block_path if block_path.is_file() else None,
    )


def _is_main_binary_function(function: Any) -> bool:
    binary = getattr(function, "binary", None)
    return bool(binary is not None and getattr(binary, "is_default", False))


def resolve_angr_icall(frontend: Any, site: int) -> ResolvedICall:
    """Resolve one absolute callsite through an angr CFGFast result."""

    project = frontend.project
    executable = tuple(
        section
        for section in project.loader.main_object.sections
        if section.is_executable
    )
    if not any(section.min_addr <= site <= section.max_addr for section in executable):
        raise InputError(
            f"Requested address {hex(site)} is outside the main binary executable sections"
        )
    cfg = project.analyses.CFGFast(force_complete_scan=False)
    candidates: dict[int, tuple[int, str]] = {}
    for function in cfg.kb.functions.values():
        if not _is_main_binary_function(function):
            continue
        for block in function.blocks:
            size = getattr(block, "size", None)
            if type(size) is int and size > 0 and block.addr <= site < block.addr + size:
                mode = "thumb" if getattr(block, "thumb", False) else "default"
                candidates[function.addr] = (block.addr, mode)
    if len(candidates) != 1:
        detail = "not recovered" if not candidates else ", ".join(map(hex, sorted(candidates)))
        raise InputError(
            f"Requested address {hex(site)} does not have one angr caller: {detail}"
        )
    caller, (block, mode) = next(iter(candidates.items()))
    return ResolvedICall(caller, site, block, mode, "angr-vex")


def _validate_indirect_site(module: CIRModule, resolved: ResolvedICall, base: int) -> None:
    matches = []
    for function in module.functions:
        if function.function_id.rva + base != resolved.caller:
            continue
        for block in function.blocks:
            for effect in block.effects:
                if (
                    isinstance(effect, CallEffect)
                    and effect.site.point.instruction_rva is not None
                    and effect.site.point.instruction_rva + base == resolved.site
                ):
                    matches.append(effect)
    if len(matches) != 1 or not isinstance(matches[0].target, IndirectTarget):
        kind = "not a lifted call" if not matches else type(matches[0].target).__name__
        raise InputError(
            f"Requested address {hex(resolved.site)} is inside function "
            f"{hex(resolved.caller)}, but is not one indirect call ({kind})"
        )


class LiveFunctionProvider:
    """In-memory CIR provider produced from IDA bounds or angr CFGFast."""

    def __init__(
        self,
        *,
        binary: Path,
        resolved: ResolvedICall,
        specifications: tuple[FunctionInput, ...],
        frontend_result: Any,
        segments: tuple[tuple[int, bytes, int, int], ...],
        loader: dict[str, object],
        plt: dict[str, int],
        provenance: dict[str, object],
    ) -> None:
        self.folder = None
        self.resolved = resolved
        self.specifications = specifications
        self.module = frontend_result.module
        self.base = int(loader["image_base"])
        self.segments = segments
        self.loader = loader
        self.plt = plt
        self.transformations: dict[int, object] = {}
        self.frontend = resolved.frontend
        self.acquisition_mode = "live"
        self.acquisition_path = None
        self.provenance = provenance
        self.report = {
            "passed": True,
            "violations": [],
            "binary_sha256": self.module.binary_sha256,
            "metadata_sha256": provenance.get("metadata_sha256"),
        }
        self.rows = {
            function.function_id.rva + self.base: function
            for function in self.module.functions
        }
        self._cfgs = {
            cfg.function: cfg for cfg in frontend_result.cfgs()
        }
        self._origins = {
            function.function_id: tuple(
                origin
                for origin in self.module.origin_map
                if origin.point.function == function.function_id
            )
            for function in self.module.functions
        }
        self._body_hashes = {
            function.function_id: hashlib.sha256(
                dumps(function, max_nodes=8_000_000, max_bytes=256 * 1024 * 1024).encode()
            ).hexdigest()
            for function in self.module.functions
        }
        self.plt_sha256 = hashlib.sha256(
            json.dumps(self.plt, sort_keys=True).encode()
        ).hexdigest()
        fingerprint = {
            "binary_sha256": self.module.binary_sha256,
            "frontend": self.frontend,
            "functions": sorted(self.rows),
            "metadata_sha256": provenance.get("metadata_sha256"),
        }
        self.frontend_fingerprint = hashlib.sha256(
            json.dumps(fingerprint, sort_keys=True).encode()
        ).hexdigest()

    def load(self, address: int) -> tuple[CIRModule, ControlFlowGraph, str]:
        function = self.rows[address]
        module = CIRModule(
            self.module.producer,
            self.module.architecture,
            self.module.endian,
            self.module.binary_sha256,
            (function,),
            self._origins[function.function_id],
            self.module.capabilities,
            self.module.assessment,
        )
        cfg = local_constant_edges(function, self._cfgs[function.function_id], self.base)
        return module, cfg, self._body_hashes[function.function_id]


class AcquisitionFunctionProvider:
    """Replay wrapper that supplies live frontend identity around FunctionStore."""

    def __init__(
        self,
        store: FunctionStore,
        discovery: LiveFunctionProvider,
        acquisition: Path,
    ) -> None:
        self._store = store
        self.resolved = discovery.resolved
        self.specifications = discovery.specifications
        self.base = store.base
        self.segments = store.segments
        self.loader = store.loader
        self.plt = store.plt
        self.plt_sha256 = store.plt_sha256
        self.transformations = store.transformations
        self.report = store.report
        self.rows = store.rows
        self.frontend = "acquisition-replay"
        self.frontend_fingerprint = hashlib.sha256(
            json.dumps(
                {
                    "binary_sha256": store.report["binary_sha256"],
                    "acquisition": str(acquisition.resolve()),
                },
                sort_keys=True,
            ).encode()
        ).hexdigest()
        self.acquisition_mode = "replay"
        self.acquisition_path = str(acquisition.resolve())
        self.provenance = {
            "frontend": self.frontend,
            "acquisition": self.acquisition_path,
        }

    def load(self, address: int):
        return self._store.load(address)


def _selected_specifications(
    specifications: tuple[FunctionInput, ...], selected: set[int]
) -> tuple[FunctionInput, ...]:
    result = tuple(specification for specification in specifications if specification.address in selected)
    missing = selected - {specification.address for specification in result}
    if missing:
        raise InputError(
            "Frontend did not recover required functions: "
            + ", ".join(map(hex, sorted(missing)))
        )
    return result


def build_live_provider(
    binary_file: str,
    site: int,
    ida_data: str | None = None,
) -> LiveFunctionProvider:
    """Build the minimum validated live frontend universe for one query."""

    binary = Path(binary_file).resolve()
    if not binary.is_file():
        raise InputError(f"Binary does not exist: {binary}")
    metadata_sha = None
    metadata_path = None
    block_path = None
    if ida_data is not None:
        from emtaint.frontends.ida_vex import IdaVexFrontend

        resolved, all_specs, metadata_path, block_path = resolve_ida_icall(
            binary, Path(ida_data).resolve(), site
        )
        frontend = IdaVexFrontend(binary)
        binary_sha = frontend.image.sha256
    else:
        from emtaint.frontends.angr_vex import AngrVexFrontend

        try:
            frontend = AngrVexFrontend(binary)
        except BaseException as error:
            raise InputError(
                "angr frontend could not start for " + str(binary) + ": " + str(error)
            ) from error
        resolved = resolve_angr_icall(frontend, site)
        binary_sha = frontend.image.sha256
        all_specs = frontend.discover(
            (resolved.caller,) + dependency_policy(binary_sha, resolved.caller, site)
        )
    selected = {resolved.caller, *dependency_policy(binary_sha, resolved.caller, site)}
    specifications = _selected_specifications(all_specs, selected)
    result = frontend.lift(specifications)
    segments, loader = relocated_image(binary)
    _validate_indirect_site(result.module, resolved, int(loader["image_base"]))
    project = getattr(frontend, "project", None)
    if project is None:
        import angr

        project = angr.Project(str(binary), auto_load_libs=False)
    plt = dict(project.loader.main_object.plt)
    if metadata_path is not None:
        metadata_sha = hashlib.sha256(metadata_path.read_bytes()).hexdigest()
    provenance = {
        "frontend": resolved.frontend,
        "binary_path": str(binary),
        "binary_sha256": result.module.binary_sha256,
        "requested_site": site,
        "requested_caller": resolved.caller,
        "metadata_path": None if metadata_path is None else str(metadata_path),
        "metadata_sha256": metadata_sha,
        "block_info_path": None if block_path is None else str(block_path),
        "packages": {
            name: _safe_version(name)
            for name in ("angr", "pyvex", "cle", "claripy", "archinfo")
        },
    }
    return LiveFunctionProvider(
        binary=binary,
        resolved=resolved,
        specifications=specifications,
        frontend_result=result,
        segments=segments,
        loader=loader,
        plt=plt,
        provenance=provenance,
    )


def build_function_provider(
    binary_file: str,
    site: int,
    *,
    ida_data: str | None = None,
    acquisition: str | None = None,
):
    """Choose replay, IDA-live, or angr-live acquisition for one query."""

    live = build_live_provider(binary_file, site, ida_data)
    if acquisition is None:
        return live
    store = FunctionStore(acquisition, binary=binary_file)
    selected = {live.resolved.caller, *dependency_policy(
        store.report["binary_sha256"], live.resolved.caller, site
    )}
    missing = selected - set(store.rows)
    if missing:
        raise InputError(
            "Acquisition is missing required functions: "
            + ", ".join(map(hex, sorted(missing)))
        )
    if store.base != live.base:
        raise InputError("Acquisition/frontend image bases differ")
    return AcquisitionFunctionProvider(store, live, Path(acquisition))


def combine_provider_modules(provider: Any, selected: set[int]):
    """Load selected provider bodies into one CIR module and CFG collection."""

    modules = []
    cfgs = []
    hashes = {}
    for address in sorted(selected):
        module, cfg, digest = provider.load(address)
        modules.append(module)
        cfgs.append(cfg)
        hashes[module.functions[0].function_id] = digest
    first = modules[0]
    combined = CIRModule(
        first.producer,
        first.architecture,
        first.endian,
        first.binary_sha256,
        tuple(function for module in modules for function in module.functions),
        tuple(origin for module in modules for origin in module.origin_map),
        first.capabilities,
        combine(module.assessment for module in modules),
    )
    return combined, tuple(cfgs), hashes
