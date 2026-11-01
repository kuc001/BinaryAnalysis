"""angr Project bytes/VEX→shared CIR lowerer, without legacy builders."""
from pathlib import Path
from ..inputs import ELFImage, InputError
from ..vex_input import check_runtime, collect_chunks, discover_inputs


class AngrVexFrontend:
    def __init__(self, binary):
        check_runtime()
        import angr
        self.path = Path(binary).resolve()
        self.image = ELFImage.from_path(self.path)
        self.project = angr.Project(str(self.path), auto_load_libs=False)
        if self.project.loader.main_object.mapped_base != self.image.image_base:
            raise InputError('angr and ELF virtual-address mappings differ; relocation must be explicit')

    def discover(self, addresses=None):
        return discover_inputs(self.project, addresses)

    def lift(self, specifications=None, *, function_addresses=None):
        from ..vex_lowering import VEXLowerer
        if specifications is None:
            specifications = self.discover(function_addresses)
        def lift(address, data, mode):
            native_address = address | 1 if mode == 'thumb' else address
            block = self.project.factory.block(native_address, size=len(data), opt_level=0,
                cross_insn_opt=False, strict_block_end=True)
            if block.bytes != data[:block.size]:
                raise InputError('angr loader bytes differ from the bound ELF image')
            return block.vex
        chunks = collect_chunks(self.image, specifications, self.project.arch, lift)
        return VEXLowerer(self.image.sha256, self.image.image_base, self.project.arch, 'angr-vex').lower(
            specifications, chunks, {'input_kind': 'angr Project', 'image_base': self.image.image_base,
                'selection': 'explicit bounds' if function_addresses is None else 'CFGFast selection'})
