"""P7 private evidence container; P3 CIR/Memory wire schemas are unchanged."""
from dataclasses import asdict,fields,is_dataclass,replace


class EvidenceEncoder:
    def __init__(self):self.recipes={}

    def dependency(self,dependency):
        result={field.name:getattr(dependency,field.name) for field in fields(dependency) if field.name!='recipes'}
        keys=[]
        for recipe in dependency.recipes:
            if recipe.key not in self.recipes:self.recipes[recipe.key]=asdict(recipe.value)
            keys.append(recipe.key)
        result['recipes']=keys
        from .demand import DeferredFormatArgument
        if isinstance(dependency.value,DeferredFormatArgument):
            result['value']={'format_slot':dependency.value.format_slot,
                'position':dependency.value.position,
                'dependency':self.dependency(dependency.value.dependency)}
        elif is_dataclass(dependency.value):result['value']=asdict(dependency.value)
        return result

    def sink(self,sink):
        result={field.name:getattr(sink,field.name) for field in fields(sink) if field.name not in ('dependencies','length_dependencies')}
        result['dependencies']=[self.dependency(dep) for dep in sink.dependencies]
        result['length_dependencies']=[self.dependency(dep) for dep in sink.length_dependencies]
        result['destinations']=[asdict(destination) for destination in sink.destinations]
        return result

    def summary(self,summary):
        return {'function':summary.function,'returns':[self.dependency(dep) for dep in summary.returns],
            'outputs':[(slot,[self.dependency(dep) for dep in dependencies]) for slot,dependencies in summary.outputs],
            'sinks':[self.sink(sink) for sink in summary.sinks],'pending':summary.pending,
            'tables':[(asdict(root),[self.dependency(dep) for dep in dependencies]) for root,dependencies in summary.tables],
            'scalar_returns':None if summary.scalar_returns is None else [self.dependency(dep) for dep in summary.scalar_returns],
            'global_outputs':None if summary.global_outputs is None else [
                {**{field.name:getattr(output,field.name) for field in fields(output) if field.name!='dependencies'},
                    'dependencies':[self.dependency(dep) for dep in output.dependencies]} for output in summary.global_outputs]}


def summary_evidence(summary,covered_sources=()):
    encoder=EvidenceEncoder();result=encoder.summary(summary)
    from .demand import dependency_order
    covered=[{'covered':encoder.dependency(narrow),'covering_input':encoder.dependency(broad)}
        for narrow,broad in sorted(covered_sources,key=lambda pair:(dependency_order(pair[0]),dependency_order(pair[1])))]
    return {'summary':result,'constraint_recipes':encoder.recipes,'evidence_format':'P7-evidence-v5',
        'covered_source_alternatives':covered}


def focused_snapshot(snapshot):
    """Close actual source facts over referenced P3 arenas, with no new DTO.

    This is a source-evidence slice, not a claim that other program effects
    are irrelevant. Full CIR/loader hashes and budgets remain replay inputs.
    """
    from emtaint.core import MemoryObjectId
    from emtaint.core.contracts import SymbolicExprId,MemoryVersionId,MemoryLocationId,AccessPathId,AccessGraphId
    definitions=((SymbolicExprId,'expressions'),(MemoryVersionId,'versions'),(MemoryLocationId,'locations'),
        (AccessPathId,'paths'),(AccessGraphId,'graphs'),(MemoryObjectId,'objects'))
    pools={kind:(name,{record.id:record for record in getattr(snapshot,name)}) for kind,name in definitions}
    chosen={name:set() for _,name in definitions};todo=list(snapshot.taint_facts)
    object_facts={record.object_id:record for record in snapshot.object_facts}
    reads={}
    for read in snapshot.reads:reads.setdefault(read.result,[]).append(read)
    selected_reads=set()
    while todo:
        value=todo.pop();kind=type(value)
        if kind in pools:
            name,index=pools[kind]
            if value in chosen[name]:continue
            if value not in index:raise ValueError('Dangling source-evidence reference: '+repr(value))
            chosen[name].add(value);todo.append(index[value])
            if kind is MemoryObjectId and value in object_facts:todo.append(object_facts[value])
            if kind is SymbolicExprId:
                for read in reads.get(value,()):
                    if read not in selected_reads:selected_reads.add(read);todo.append(read)
        elif is_dataclass(value):todo.extend(getattr(value,field.name) for field in fields(value))
        elif type(value) is tuple:todo.extend(value)
    parts={name:tuple(record for record in getattr(snapshot,name) if record.id in chosen[name]) for _,name in definitions}
    parts['reads']=tuple(read for read in snapshot.reads if read in selected_reads)
    parts['object_facts']=tuple(record for record in snapshot.object_facts if record.object_id in chosen['objects'])
    parts['cells']=tuple(cell for cell in snapshot.cells if cell.location in chosen['locations']
        and cell.value in chosen['expressions'] and cell.defined_in in chosen['versions'])
    return replace(snapshot,**parts)
