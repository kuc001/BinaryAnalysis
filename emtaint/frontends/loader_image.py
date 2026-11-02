"""Snapshot a CLE-relocated image while retaining explicit provenance."""

from __future__ import annotations

import hashlib
from os import PathLike

from .inputs import ELFImage, InputError


def relocated_image(
    binary: str | PathLike[str],
) -> tuple[tuple[tuple[int, bytes, int, int], ...], dict[str, object]]:
    """Load an executable with CLE and return immutable mapped segment bytes.

    The loader base must equal the ET_EXEC link-time image base. This prevents a
    silent relocation policy change at the frontend boundary.
    """

    import angr

    image = ELFImage.from_path(binary)
    project = angr.Project(str(binary), auto_load_libs=False)
    if project.loader.main_object.mapped_base != image.image_base:
        raise InputError('Relocated loader mapping differs from declared CIR image base')
    segments = tuple(
        (base, bytes(project.loader.memory.load(base, mem_size)), mem_size, flags)
        for base, _offset, _size, mem_size, flags in image.segments
    )
    provenance: dict[str, object] = {
        'binary_sha256': image.sha256,
        'policy': 'CLE relocated loader snapshot; auto_load_libs=False',
        'image_base': image.image_base,
        'segments': [
            {
                'base': base,
                'size': mem_size,
                'flags': flags,
                'sha256': hashlib.sha256(data).hexdigest(),
            }
            for base, data, mem_size, flags in segments
        ],
        'sections': {
            section.name: (section.min_addr, section.max_addr + 1)
            for section in project.loader.main_object.sections
            if section.name
        },
        'relocations': len(project.loader.main_object.relocs),
    }
    return segments, provenance
