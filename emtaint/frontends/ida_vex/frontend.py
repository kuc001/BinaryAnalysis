"""Read-only existing IDA JSON + ELF bytes→native VEX→shared CIR lowerer."""
import hashlib
from pathlib import Path

from ..inputs import ELFImage, read_ida_cfg
from ..vex_input import check_runtime, collect_chunks, native_arch


class IdaVexFrontend:
    def __init__(self, binary):
        check_runtime()
        self.path = Path(binary).resolve()
        self.image = ELFImage.from_path(self.path)
        self.arch = native_arch(self.image)

    def lift(self, specifications):
        import pyvex
        from ..vex_lowering import VEXLowerer
        def lift(address, data, mode):
            return pyvex.IRSB(data, address | 1 if mode == 'thumb' else address, self.arch,
                bytes_offset=1 if mode == 'thumb' else 0, max_bytes=len(data),
                opt_level=0, cross_insn_opt=False, strict_block_end=True)
        chunks = collect_chunks(self.image, specifications, self.arch, lift)
        return VEXLowerer(self.image.sha256, self.image.image_base, self.arch, 'ida-metadata-vex').lower(
            specifications, chunks, {'input_kind': 'ELF bytes at linked virtual addresses',
                'image_base': self.image.image_base,
                'ida_edges': {hex(s.address): list(s.edges) for s in specifications},
                'ida_calls': {hex(s.address): [vars(c) for c in s.calls] for s in specifications}})

    def from_metadata(self, metadata, *, function_addresses=None, mode='default'):
        specifications = read_ida_cfg(metadata, mode=mode)
        if function_addresses is not None:
            requested = set(function_addresses)
            specifications = tuple(s for s in specifications if s.address in requested)
            if {s.address for s in specifications} != requested:
                from ..inputs import InputError
                raise InputError('Requested IDA function missing from metadata')
        result = self.lift(specifications)
        result.metadata['ida_metadata_sha256'] = hashlib.sha256(Path(metadata).read_bytes()).hexdigest()
        result.metadata['ida_metadata_source'] = str(Path(metadata).resolve())
        return result
