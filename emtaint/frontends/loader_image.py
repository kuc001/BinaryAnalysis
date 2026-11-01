"""CLE relocation boundary. Only immutable plain bytes leave the frontend."""
import hashlib
from .inputs import ELFImage,InputError


def relocated_image(binary):
    import angr
    image=ELFImage.from_path(binary)
    project=angr.Project(str(binary),auto_load_libs=False)
    if project.loader.main_object.mapped_base!=image.image_base:
        raise InputError('Relocated loader mapping differs from declared CIR image base')
    segments=tuple((base,bytes(project.loader.memory.load(base,memsz)),memsz,flags)
                   for base,offset,size,memsz,flags in image.segments)
    provenance={'binary_sha256':image.sha256,'policy':'CLE relocated loader snapshot; auto_load_libs=False',
        'image_base':image.image_base,'segments':[
            {'base':base,'size':memsz,'flags':flags,'sha256':hashlib.sha256(data).hexdigest()}
            for base,data,memsz,flags in segments],
        'sections':{s.name:(s.min_addr,s.max_addr+1) for s in project.loader.main_object.sections if s.name},
        'relocations':len(project.loader.main_object.relocs)}
    return segments,provenance
