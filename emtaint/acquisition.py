"""The bounded F0 Project-to-CIR acquisition use case."""

from __future__ import annotations

from dataclasses import dataclass
import importlib.metadata

from emtaint.artifacts import (
    AcquisitionRef, ArtifactRoot, FunctionInputs, IntegrityStatus,
    SemanticCompleteness, load, publish,
)
from emtaint.core import FunctionId
from emtaint.frontends.angr_vex import AngrVexFrontend
from emtaint.frontends.inputs import InputError
from emtaint.project import ResolvedInputs


@dataclass(frozen=True)
class FrontendSelection:
    """The one native frontend supported by F0."""

    name: str = "angr-vex"

    def __post_init__(self) -> None:
        if self.name != "angr-vex":
            raise InputError("F0 supports only angr-vex")


@dataclass(frozen=True)
class AcquisitionOutcome:
    """Published reference and separate integrity/semantic states."""

    reference: AcquisitionRef
    function: FunctionId
    integrity: IntegrityStatus
    semantic_completeness: SemanticCompleteness
    diagnostics: tuple[str, ...]


def acquire(
    inputs: ResolvedInputs,
    selection: FrontendSelection,
    artifact_root: ArtifactRoot,
) -> AcquisitionOutcome:
    """Discover and lift a real function, then publish verified artifacts.

    Discovery/lifting failures are explicit; this service does not synthesize
    a FunctionInput, silently select another function or invoke analysis.
    """

    if type(inputs) is not ResolvedInputs or type(selection) is not FrontendSelection:
        raise TypeError("acquire requires ResolvedInputs and FrontendSelection")
    if type(artifact_root) is not ArtifactRoot:
        raise TypeError("acquire requires ArtifactRoot")
    if selection.name != inputs.spec.frontend:
        raise InputError("Frontend selection differs from Project")
    frontend = AngrVexFrontend(inputs.spec.binary_path)
    if (frontend.image.sha256 != inputs.binary_id.sha256
            or frontend.image.data != inputs.binary_bytes
            or frontend.image.image_base != inputs.image_base
            or frontend.image.machine != inputs.machine
            or tuple(frontend.image.segments) != inputs.segments
            or frontend.project.loader.main_object.mapped_base != inputs.image_base):
        raise InputError("Native loader/binary mapping differs from resolved Project")
    specifications = frontend.discover((inputs.selected_va,))
    if len(specifications) != 1 or specifications[0].address != inputs.physical_va:
        raise InputError("CFGFast did not recover the selected physical function")
    entry_blocks = tuple(block for block in specifications[0].blocks
                         if block.start == inputs.physical_va)
    if (len(entry_blocks) != 1
            or (inputs.instruction_mode == "thumb") != (entry_blocks[0].mode == "thumb")):
        raise InputError("CFGFast entry instruction mode differs from Project VA")
    result = frontend.lift(specifications)
    if len(result.module.functions) != 1:
        raise InputError("Frontend did not return one selected function")
    function = result.module.functions[0].function_id
    if function != FunctionId(inputs.binary_id, inputs.function_rva):
        raise InputError("Frontend FunctionId differs from Project address conversion")
    cfgs = result.cfgs()
    if len(cfgs) != 1 or result.provenance is None:
        raise InputError("Frontend omitted CFG or provenance")
    report = result.report()
    tool_versions = {
        name: importlib.metadata.version(name)
        for name in ("angr", "pyvex", "archinfo", "cle", "claripy")
    }
    reference = publish(
        inputs, result.module, cfgs[0], result.provenance, report,
        tool_versions, artifact_root,
    )
    # Re-read the published generation rather than trusting the staging check
    # alone; the returned receipt is pinned to the bytes now visible to readers.
    loaded: FunctionInputs = load(reference, function)
    return AcquisitionOutcome(
        reference, function, loaded.integrity,
        loaded.semantic_completeness, loaded.diagnostics,
    )
