"""Bounded replay of a saved CIR acquisition; no native frontend is imported."""

from __future__ import annotations

import hashlib
import json
from os import PathLike
from pathlib import Path

from emtaint.core import FunctionId, ProgramPoint
from emtaint.core.contracts import Origin
from emtaint.ir.canonical import CIRModule
from emtaint.ir.canonical.wire import loads

from .inputs import InputError


def load_saved_cir(
    folder: str | PathLike[str], max_bytes: int = 256 * 1024 * 1024
) -> tuple[CIRModule, object, dict[FunctionId, str]]:
    """Reconstruct one bounded CIR acquisition from immutable saved artifacts.

    Args:
        folder: Acquisition directory containing CIR bodies and provenance files.
        max_bytes: Per-body decode limit and aggregate CIR body byte budget.

    Returns:
        The reconstructed module, its JSON report, and hashes of source bodies.

    Raises:
        InputError: If the byte budget is invalid, exceeded, or no bodies exist.
        OSError: If a required acquisition artifact cannot be read.
        ValueError: If a wire or JSON artifact violates its declared format.
    """

    if type(max_bytes) is not int or max_bytes <= 0:
        raise InputError('Saved CIR acquisition byte budget must be positive')
    folder_path = Path(folder)
    files = sorted((folder_path / 'cir').glob('function-*.json'))
    if not files or sum(file.stat().st_size for file in files) > max_bytes:
        raise InputError('Saved CIR acquisition byte budget')
    return decode_saved_cir(
        tuple(file.read_bytes() for file in files),
        (folder_path / 'architecture.json').read_bytes(),
        (folder_path / 'producer.json').read_bytes(),
        (folder_path / 'assessment.json').read_bytes(),
        (folder_path / 'origins.json').read_bytes(),
        (folder_path / 'frontend-report.json').read_bytes(),
        max_bytes=max_bytes,
    )


def decode_saved_cir(
    function_bodies: tuple[bytes, ...],
    architecture_body: bytes,
    producer_body: bytes,
    assessment_body: bytes,
    origins_body: bytes,
    report_body: bytes,
    *,
    max_bytes: int = 256 * 1024 * 1024,
) -> tuple[CIRModule, object, dict[FunctionId, str]]:
    """Decode already-read CIR bytes, preserving the saved-CIR v1 layout.

    A verified artifact reader can supply pinned, hash-checked bytes here, so
    decoding never reopens a potentially changed file after validation.
    """

    if not function_bodies or sum(map(len, function_bodies)) > max_bytes:
        raise InputError('Saved CIR acquisition byte budget')
    functions = tuple(
        loads(body.decode('utf8'), max_nodes=8_000_000, max_bytes=max_bytes)
        for body in function_bodies
    )
    architecture = loads(architecture_body.decode('utf8'))
    producer = loads(producer_body.decode('utf8'))
    assessment = loads(assessment_body.decode('utf8'))
    metadata = json.loads(origins_body.decode('utf8'))
    if type(metadata) is not dict:
        raise InputError('Saved CIR origins must be a JSON object')
    blocks = {
        block.id.token: block.id
        for function in functions
        for block in function.blocks
    }
    origins = tuple(
        Origin(
            name,
            ProgramPoint(
                blocks[row['block']],
                row['statement_index'],
                row['instruction_rva'],
            ),
            producer,
            row['source_opcode'],
        )
        for name, row in metadata.items()
    )
    module = CIRModule(
        producer,
        architecture,
        architecture.endian,
        functions[0].function_id.binary.sha256,
        functions,
        origins,
        ('typed-effects',),
        assessment,
    )
    report = json.loads(report_body.decode('utf8'))
    body_hashes = {
        function.function_id: hashlib.sha256(body).hexdigest()
        for function, body in zip(functions, function_bodies)
    }
    return module, report, body_hashes
