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
    functions = tuple(
        loads(
            file.read_text(encoding='utf8'),
            max_nodes=8_000_000,
            max_bytes=max_bytes,
        )
        for file in files
    )
    architecture = loads((folder_path / 'architecture.json').read_text(encoding='utf8'))
    producer = loads((folder_path / 'producer.json').read_text(encoding='utf8'))
    assessment = loads((folder_path / 'assessment.json').read_text(encoding='utf8'))
    metadata = json.loads((folder_path / 'origins.json').read_text(encoding='utf8'))
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
    report = json.loads(
        (folder_path / 'frontend-report.json').read_text(encoding='utf8')
    )
    body_hashes = {
        function.function_id: hashlib.sha256(file.read_bytes()).hexdigest()
        for function, file in zip(functions, files)
    }
    return module, report, body_hashes
