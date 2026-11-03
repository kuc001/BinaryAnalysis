"""Snapshot a CLE-relocated image while retaining explicit provenance."""

from __future__ import annotations

import hashlib
from os import PathLike

from .inputs import ELFImage, InputError


def relocated_image(
    binary: str | PathLike[str],
) -> tuple[tuple[tuple[int, bytes, int, int], ...], dict[str, object]]:
    """Load an executable with CLE and return immutable mapped segment bytes.

    ET_EXEC retains its link-time base. ET_DYN uses CLE's explicit mapped base;
    the frontend never guesses a PIE relocation independently.
    """

    import angr

    project = angr.Project(str(binary), auto_load_libs=False)
    image = ELFImage.from_path(
        binary,
        load_base=project.loader.main_object.mapped_base,
    )
    if project.loader.main_object.mapped_base != image.image_base:
        raise InputError('Relocated loader mapping differs from declared CIR image base')
    segments = tuple(
        (base, bytes(project.loader.memory.load(base, mem_size)), mem_size, flags)
        for base, _offset, _size, mem_size, flags in image.segments
    )
    provenance: dict[str, object] = {
        'binary_sha256': image.sha256,
        'policy': 'CLE explicit-base relocated loader snapshot; auto_load_libs=False',
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
