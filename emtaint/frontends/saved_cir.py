"""Bounded replay of a saved CIR acquisition; no native frontend is imported."""
import hashlib
import json
from pathlib import Path
from emtaint.core import ProgramPoint
from emtaint.core.contracts import Origin
from emtaint.ir.canonical import CIRModule
from emtaint.ir.canonical.wire import loads
from .inputs import InputError


def load_saved_cir(folder,max_bytes=256*1024*1024):
    folder=Path(folder);files=sorted((folder/'cir').glob('function-*.json'))
    if not files or sum(f.stat().st_size for f in files)>max_bytes:raise InputError('Saved CIR acquisition byte budget')
    functions=tuple(loads(f.read_text(encoding='utf8'),max_nodes=8000000,max_bytes=max_bytes) for f in files)
    architecture=loads((folder/'architecture.json').read_text(encoding='utf8'))
    producer=loads((folder/'producer.json').read_text(encoding='utf8'))
    assessment=loads((folder/'assessment.json').read_text(encoding='utf8'))
    metadata=json.loads((folder/'origins.json').read_text(encoding='utf8'))
    blocks={b.id.token:b.id for function in functions for b in function.blocks}
    origins=tuple(Origin(name,ProgramPoint(blocks[row['block']],row['statement_index'],row['instruction_rva']),producer,row['source_opcode'])
                  for name,row in metadata.items())
    module=CIRModule(producer,architecture,architecture.endian,functions[0].function_id.binary.sha256,
                     functions,origins,('typed-effects',),assessment)
    report=json.loads((folder/'frontend-report.json').read_text(encoding='utf8'))
    body_hashes={f.function_id:hashlib.sha256(file.read_bytes()).hexdigest() for f,file in zip(functions,files)}
    return module,report,body_hashes
