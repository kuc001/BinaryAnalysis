"""Pure reader for bounded per-function P7 CIR acquisitions."""
import hashlib
import json
from pathlib import Path
from emtaint.ir.canonical.wire import loads
from emtaint.ir.canonical import CIRModule
from emtaint.graph import ControlFlowGraph,FlowEdge,FlowKind
from emtaint.analysis.controlflow.local_constants import local_constant_edges,ida_metadata_edges


class FunctionStore:
    def __init__(self,folder,*,binary=None):
        self.folder=Path(folder);self.report=json.loads((self.folder/'acquisition-report.json').read_text(encoding='utf8'))
        if not self.report['passed'] or self.report['violations']:raise ValueError('A successful immutable acquisition is required')
        self.loader=json.loads((self.folder/'loader.json').read_text(encoding='utf8'))
        self.rows={r['function']:r for r in self.report['rows']};self.base=self.loader['image_base']
        self.segments=tuple((s['base'],(self.folder/s['file']).read_bytes(),s['size'],s['flags']) for s in self.loader['segments'])
        for row,(_,data,_,_) in zip(self.loader['segments'],self.segments):
            if hashlib.sha256(data).hexdigest()!=row['sha256']:raise ValueError('Loader hash mismatch')
        self.plt={};self.complete_tails=binary is not None;self.transformations={}
        if binary is not None:
            if hashlib.sha256(Path(binary).read_bytes()).hexdigest()!=self.report['binary_sha256']:raise ValueError('Tail-call binary hash mismatch')
            import angr
            project=angr.Project(str(binary),auto_load_libs=False)
            self.plt=dict(project.loader.main_object.plt)
        self.plt_sha256=hashlib.sha256(json.dumps(self.plt,sort_keys=True).encode()).hexdigest()

    def load(self,address):
        row=self.rows[address];folder=self.folder/row['directory'];data=(folder/'function.json').read_bytes()
        if hashlib.sha256(data).hexdigest()!=row['cir_sha256']:raise ValueError('CIR body hash mismatch')
        function=loads(data.decode('utf8'),max_nodes=8000000,max_bytes=256*1024*1024)
        origins=tuple(loads(line) for line in (folder/'origins.jsonl').read_text(encoding='utf8').splitlines())
        read=lambda name:loads((folder/(name+'.json')).read_text(encoding='utf8'))
        module=CIRModule(read('producer'),read('architecture'),read('architecture').endian,self.report['binary_sha256'],
                         (function,),origins,('typed-effects',),read('assessment'))
        metadata=json.loads((folder/'frontend.json').read_text(encoding='utf8'));blocks={b.id.token:b.id for b in function.blocks}
        cfg=ControlFlowGraph(function.function_id,frozenset(blocks.values()),frozenset(
            FlowEdge(blocks[a],blocks[b],FlowKind(kind),label) for a,b,kind,label in metadata['cfgs'][0]['edges']),function.entry)
        cfg=local_constant_edges(function,cfg,self.base)
        cfg=ida_metadata_edges(function,cfg,metadata['block_mappings'],metadata['metadata']['ida_edges'].get(hex(address),()),self.base)
        if self.complete_tails:
            from .tail_calls import complete_tail_calls
            from emtaint.ir.canonical.wire import dumps
            module,cfg,receipts=complete_tail_calls(module,cfg,metadata['metadata']['ida_calls'].get(hex(address),()),self.base,self.plt)
            derived=hashlib.sha256(dumps(module.functions[0],max_nodes=8000000,max_bytes=256*1024*1024).encode()).hexdigest() if receipts else row['cir_sha256']
            self.transformations[address]={'acquired_sha256':row['cir_sha256'],'derived_sha256':derived,'tail_calls':receipts}
            return module,cfg,derived
        return module,cfg,row['cir_sha256']

    def program_index(self,specifications):
        """Stream body headers into P2 metadata; retain no whole-program CIR."""
        from emtaint.core import Program,Function,BasicBlock,CallSite,CallKind,FunctionId,ProgramPoint,CallSiteId,Completeness
        from emtaint.graph import CallGraph,CallEdge,TargetKind
        from emtaint.frontends.program_index import ProgramIndex
        functions=[];sites={};edges=set();external=[];cfgs=[];native_only=[];first=None
        specs={s.address:s for s in specifications}
        decode=lambda value:loads(json.dumps(value))
        for address,row in sorted(self.rows.items()):
            folder=self.folder/row['directory'];data=(folder/'function.json').read_bytes()
            if hashlib.sha256(data).hexdigest()!=row['cir_sha256']:raise ValueError('CIR header hash mismatch')
            raw=json.loads(data);fid=decode(raw['function_id']);entry=decode(raw['entry']);spec=specs[address]
            blocks=[];native={};extents={}
            for line in (folder/'origins.jsonl').open(encoding='utf8'):
                point=json.loads(line)['point'];bid=point['block'];instruction=point['instruction_rva']
                if instruction is not None:
                    key=(bid['rva'],bid['index'],bid['mode'])
                    extents[key]=max(extents.get(key,1),instruction-bid['rva']+1)
            for block in raw['blocks']:
                bid=decode(block['id']);size=max(block['size_bytes'] or 1,extents.get((bid.rva,bid.index,bid.mode),1))
                for effect in block['effects']:
                    if effect['$type']=='CallEffect':
                        site=decode(effect['site']);native[site.point.instruction_rva+self.base]=site
                        if site.point.instruction_rva is not None:size=max(size,site.point.instruction_rva-bid.rva+1)
                blocks.append(BasicBlock(bid,size))
            functions.append(Function(fid,spec.name,tuple(blocks),entry))
            metadata=json.loads((folder/'frontend.json').read_text(encoding='utf8'));mapped={b.id.token:b.id for b in blocks}
            cfgs.append(ControlFlowGraph(fid,frozenset(mapped.values()),frozenset(FlowEdge(mapped[a],mapped[b],FlowKind(kind),label)
                for a,b,kind,label in metadata['cfgs'][0]['edges']),entry))
            used=set()
            for call in spec.calls:
                if not any(b.start==call.block and not b.boundary for b in spec.blocks):continue
                site=native.get(call.instruction)
                if site is None:
                    candidates=[b for b in blocks if b.id.rva<=call.instruction-self.base<b.id.rva+b.size]
                    if not candidates:raise ValueError('Metadata call is outside acquired block extents '+hex(call.instruction))
                    block=min(candidates,key=lambda b:(b.size,b.id.index))
                    site=CallSiteId(ProgramPoint(block.id,None,call.instruction-self.base))
                used.add(call.instruction);sites[site]=CallSite(site,CallKind.DIRECT if type(call.target) is int else CallKind.EXTERNAL)
                if type(call.target) is int:
                    target=FunctionId(fid.binary,call.target-self.base);edges.add(CallEdge(site,target,TargetKind.CONFIRMED,'Original IDA static call metadata'))
                else:
                    edges.add(CallEdge(site,None,TargetKind.UNKNOWN,'Original IDA external/unknown call: '+call.target));external.append((fid,site,call.target))
            for instruction,site in native.items():
                if instruction in used:continue
                sites[site]=CallSite(site,CallKind.UNKNOWN);edges.add(CallEdge(site,None,TargetKind.UNKNOWN,'Native call has no original static target'));native_only.append(site)
            if first is None:first=folder,raw['abi'],fid.binary
        folder,abi,binary=first
        architecture=loads((folder/'architecture.json').read_text(encoding='utf8'))
        program=Program(binary,architecture,decode(abi),tuple(functions),tuple(sites.values()),self.base,
            Completeness.INCOMPLETE,('Complete acquired function universe; external effects and unresolved indirect calls remain explicit',))
        graph=CallGraph(frozenset(f.id for f in functions),frozenset(edges),Completeness.INCOMPLETE,'Acquired CIR/IDA cold dependencies')
        return ProgramIndex(program,graph,tuple(cfgs),tuple(external),tuple(native_only))
