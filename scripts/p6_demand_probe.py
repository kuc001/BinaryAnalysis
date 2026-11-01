"""Demand analysis of saved, immutable CIR; Golden opened after collection."""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import sys
import time
import traceback
import uuid

TARGET=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(TARGET));sys.path.insert(0,str(TARGET/'tests'))
from p1_runtime import ProbeWriteGuard
from emtaint.core import Architecture,Endian,ContextId,ProgramPoint,BlockId
from emtaint.core.contracts import Origin,Producer,AnalysisScope,SemanticBudgets
from emtaint.ir.canonical import BranchEffect,JumpEffect,CallEffect,IndirectTarget,ReturnEffect
from emtaint.ir.canonical.wire import loads,dumps
from emtaint.graph import ControlFlowGraph,FlowEdge,FlowKind
from emtaint.frontends.inputs import ELFImage
from emtaint.memory.image import ImageMemoryEngine
from emtaint.compat.memory_runtime import MemoryRuntimePort
from emtaint.analysis.dataflow.accurate import CIRAccurateDataFlow
from emtaint.analysis.dataflow.entry import legacy_entry
from emtaint.analysis.dataflow.legacy_demand import LegacyDemand,DemandLimit,DemandBudget
from emtaint.analysis.controlflow.local_constants import local_constant_edges,ida_metadata_edges
from emtaint.analysis.controlflow.legacy_tables import LegacyTableCollector
from emtaint.analysis.framework.summaries import compile_recipe
from emtaint.compat.legacy_icall_policy import legacy_maximum_address


def write(path,value):
    with path.open('x',encoding='utf8') as stream:json.dump(value,stream,indent=2)

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--folder',type=Path,required=True)
    parser.add_argument('--cir-folder',type=Path,required=True)
    parser.add_argument('--loader',type=Path,required=True)
    parser.add_argument('--functions',type=lambda s:int(s,0),nargs='+')
    args=parser.parse_args();folder=args.folder.resolve();folder.relative_to(TARGET/'.p6-work');folder.mkdir(exist_ok=False)
    guard=ProbeWriteGuard([folder]).install();results=[]
    try:
        source=args.cir_folder.resolve();source.relative_to(TARGET/'.p6-work')
        report=json.loads((source/'frontend-report.json').read_text(encoding='utf8'))
        by_origin={r['origin']:r for r in report['coverage']}
        origin_metadata=json.loads((source/'origins.json').read_text(encoding='utf8')) if (source/'origins.json').exists() else {}
        image=ELFImage.from_path(TARGET.parent/'EmTaint/firmware-binaries/rv130_v44/httpd')
        # Native input is ELF32 little endian. Section bounds match the old
        # Collector section_regions, rather than accepting whole PT_LOAD code.
        if image.elf_class!=1 or image.encoding!=1:raise ValueError('This rv130 probe requires ELF32 LE')
        shoff=struct.unpack_from('<I',image.data,32)[0]
        entsize,count,strings=struct.unpack_from('<HHH',image.data,46)
        rows=[struct.unpack_from('<IIIIIIIIII',image.data,shoff+i*entsize) for i in range(count)]
        string_data=image.data[rows[strings][4]:rows[strings][4]+rows[strings][5]]
        sections={string_data[r[0]:].split(b'\0')[0].decode('ascii'):(r[3],r[3]+r[5]) for r in rows}
        text=sections['.text'];is_code=lambda x:text[0]<=x<=text[1]
        is_data=lambda x:any(a<=x<=b for n,(a,b) in sections.items() if n in ('.data','.rodata','.bss'))
        loader=json.loads((args.loader/'loader.json').read_text(encoding='utf8'))
        if loader['binary_sha256']!=image.sha256 or not loader['passed']:raise ValueError('Loader snapshot identity/failure')
        segments=tuple((s['base'],(args.loader/s['file']).read_bytes(),s['memsz'],s['flags']) for s in loader['segments'])
        if any(hashlib.sha256(data).hexdigest()!=s['sha256'] for (_,data,_,_),s in zip(segments,loader['segments'])):raise ValueError('Loader bytes changed')
        data=TARGET.parent/'EmTaint/data/ida_data/rv130_1_0_3_44'
        info=json.loads((data/'httpd_block_info.json').read_text(encoding='utf8'))
        sites={(int(f,16),row[0]) for f,blocks in info.items() for rows_ in blocks.values() for row in rows_ if row[-1]=='iCall'}
        summaries={};summary_rows=[]
        for file in sorted((source/'cir').glob('*.json')):
            f=loads(file.read_text(encoding='utf8'),max_nodes=8000000,max_bytes=256*1024*1024)
            if args.functions and f.function_id.rva+image.image_base not in args.functions:continue
            origins={}
            block_ids={b.id.token:b.id for b in f.blocks}
            for block in f.blocks:
                for effect in block.effects:
                    if effect.origin in origin_metadata:
                        row=origin_metadata[effect.origin]
                        point=ProgramPoint(block_ids[row['block']],row['statement_index'],row['instruction_rva'])
                    else:
                        row=by_origin[effect.origin]
                        point=ProgramPoint(block.id,row['statement_index'],row['instruction']-image.image_base)
                    origins.setdefault(effect.origin,Origin(effect.origin,point,Producer('saved-CIR-demand','1','pure-CIR'),row['source_opcode']))
            scope=AnalysisScope(f.function_id,ContextId(),'p6-demand-'+uuid.uuid4().hex,0,0)
            engine=ImageMemoryEngine(scope,Architecture('ARMEL',32,32,Endian.LITTLE),tuple(origins.values()),segments,
                SemanticBudgets(sse_nodes=200000,worklist_iterations=2000000),initial_policy='legacy-loader-snapshot')
            port=MemoryRuntimePort(engine);initial=legacy_entry(CIRAccurateDataFlow(port))
            edges=set()
            for block in f.blocks:
                for effect in block.effects:
                    if isinstance(effect,BranchEffect):
                        edges.add(FlowEdge(block.id,effect.if_true,FlowKind.TRUE));edges.add(FlowEdge(block.id,effect.if_false,FlowKind.FALSE))
                    elif isinstance(effect,JumpEffect) and isinstance(effect.target,BlockId):edges.add(FlowEdge(block.id,effect.target,FlowKind.JUMP))
            cfg=local_constant_edges(f,ControlFlowGraph(f.function_id,frozenset(b.id for b in f.blocks),frozenset(edges),f.entry),image.image_base)
            cfg=ida_metadata_edges(f,cfg,report['block_mappings'],
                report['metadata']['ida_edges'].get(hex(f.function_id.rva+image.image_base),()),image.image_base)
            demand=LegacyDemand(f,port,cfg,initial,budget=DemandBudget(depth=500,steps=250000),summaries=summaries)
            if not any(caller==f.function_id.rva+image.image_base for caller,site in sites):
                return_values=[]
                for block in f.blocks:
                    for effect in block.effects:
                        if isinstance(effect,ReturnEffect):
                            for value in effect.values:return_values.extend(demand.value(value))
                if return_values:
                    recipe=compile_recipe(demand,return_values,provenance=(
                        'Actual callee CIR SHA256 '+hashlib.sha256(file.read_bytes()).hexdigest(),
                        'Legacy _update_expr_from_callees return/argument substitution'))
                    summaries[f.function_id]=recipe
                    summary_rows.append({'function':f.function_id.rva+image.image_base,'nodes':len(recipe.nodes),
                        'returns':len(recipe.returns),'argument_uses':recipe.argument_uses,'write_regions':recipe.write_regions})
            for block in f.blocks:
                for effect in block.effects:
                    site=origins[effect.origin].point.instruction_rva+image.image_base;caller=f.function_id.rva+image.image_base
                    if (caller,site) not in sites:continue
                    if isinstance(effect,ReturnEffect):
                        row={'function':caller,'site':site,'targets':[],
                            'classification':'IDA iCall annotation is native Ijk_Ret',
                            'instruction_bytes':image.read(site,4).hex(),
                            'evidence':'CIR ReturnEffect; saved VEX jumpkind; ARM LDR pc,[sp],#8 is an epilogue return',
                            'cir_sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
                        results.append(row);write(folder/('site-'+hex(caller)+'-'+hex(site)+'.json'),row)
                        continue
                    operand=effect.target.address if isinstance(effect,CallEffect) and isinstance(effect.target,IndirectTarget) else effect.target if isinstance(effect,JumpEffect) and not isinstance(effect.target,BlockId) else None
                    if operand is None:continue
                    started=time.monotonic();row={'function':caller,'site':site,'cir_sha256':hashlib.sha256(file.read_bytes()).hexdigest()}
                    reached={f.entry};todo=[f.entry]
                    while todo:
                        node=todo.pop()
                        for successor in cfg.successors(node):
                            if successor not in reached:reached.add(successor);todo.append(successor)
                    row.update(cfg_reachable=block.id in reached,cfg_reachable_blocks=len(reached),cfg_blocks=len(f.blocks))
                    try:
                        refs=demand.value(operand);collector=LegacyTableCollector(demand,is_code,is_data)
                        maximum=legacy_maximum_address(image.sha256,site)
                        targets=sorted({target for ref in refs for target in collector.collect(ref,maximum_address=maximum)})
                        row.update(targets=targets,expressions=[r.key for r in refs],evidence=collector.evidence,
                            notes=sorted(set(demand.notes)),rules=sorted(demand.rules),steps=demand.steps,metrics=port.metrics())
                    except (DemandLimit,RecursionError,ValueError) as error:
                        row.update(targets=[],error=type(error).__name__+': '+str(error),steps=demand.steps)
                        traceback.print_exc()
                    row['wall_seconds']=time.monotonic()-started;results.append(row)
                    write(folder/('site-'+hex(caller)+'-'+hex(site)+'.json'),row)
                    print(hex(caller),hex(site),len(row['targets']),row.get('error',''),flush=True)
            with (folder/('dag-'+hex(f.function_id.rva)+'.json')).open('x',encoding='utf8') as stream:
                stream.write(dumps(engine.snapshot(),max_nodes=8000000,max_bytes=256*1024*1024))
            write(folder/('loads-'+hex(f.function_id.rva)+'.json'),
                {ref.key:{'address':a.key,'width':w,'endian':en.value,'origin':o} for ref,(a,w,en,o) in demand.loads.items()})
        write(folder/'derived-targets.json',results)
        write(folder/'summaries.json',summary_rows)
        golden=json.loads((TARGET.parent/'baselines/rv130_1_0_3_44/20261028T051055Z-96d1c781/icall-targets.json').read_text(encoding='utf8'))
        for row in results:
            old=set(golden.get(str(row['function']),{}).get(str(row['site']),[]));new=set(row['targets'])
            row.update(missing=sorted(old-new),extra=sorted(new-old))
        write(folder/'comparison.json',results);write(folder/'guard.json',{'violations':guard.violations})
    finally:guard.restore()
    return 0

if __name__=='__main__':raise SystemExit(main())
