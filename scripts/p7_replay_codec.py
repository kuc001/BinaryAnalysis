"""Strict reader for private P7 evidence, used only by replay diagnostics.

P3 CIR/Memory schema is unchanged. Recipes are hash checked before a replay
can instantiate them in a new function scope; no scoped IDs are imported.
"""
from dataclasses import fields
import json
from emtaint.core import BinaryId,FunctionId,Endian
from emtaint.core.contracts import ValueType,TypeKind,Signedness
from emtaint.analysis.framework.summaries import ProcedureRecipe,SummaryNode,SummaryStore
from emtaint.analysis.taint.demand import (ConstraintRecipe,TaintDependency,TaintProcedureSummary,
    SinkRequirement,BufferDestination,DeferredFormatArgument)
from emtaint.analysis.taint.tables import TableRoot
from emtaint.analysis.taint.global_outputs import GlobalTaintOutput
from emtaint.procedures.legacy import lookup


def frozen(value):
    if type(value) is list:return tuple(frozen(item) for item in value)
    if value is None or type(value) in (int,bool,str):return value
    raise ValueError('Unsupported private evidence value')


def checked_keys(cls,value,optional=()):
    allowed={field.name for field in fields(cls)}
    if not isinstance(value,dict) or set(value)-allowed or allowed-set(value)-set(optional):raise ValueError('Unexpected '+cls.__name__+' fields')


def recipe(value):
    checked_keys(ProcedureRecipe,value)
    fid=value['function'];function=FunctionId(BinaryId(fid['binary']['sha256']),fid['rva'])
    nodes=[]
    for row in value['nodes']:
        checked_keys(SummaryNode,row)
        type_=row['type'];checked_keys(ValueType,type_)
        type_=ValueType(TypeKind(type_['kind']),type_['bits'],Signedness(type_['signedness']),type_['address_space'])
        operands=frozen(row['operands'])
        if any(type(index) is not int or not 0<=index<len(nodes) for index in operands):raise ValueError('Recipe is not a finite topological DAG')
        nodes.append(SummaryNode(type_,row['op'],operands,frozen(row['value']),frozen(row['params']),row['origin'],
            None if row['endian'] is None else Endian(row['endian'])))
    stores=[]
    for row in value['stores']:
        checked_keys(SummaryStore,row)
        stores.append(SummaryStore(frozen(row['addresses']),frozen(row['values']),row['width_bits'],Endian(row['endian']),
            row['origin'],frozen(row['guards']),row['must_execute']))
    return ProcedureRecipe(function,tuple(nodes),frozen(value['returns']),tuple(stores),frozen(value['argument_uses']),
        frozen(value['provenance']),frozen(value['write_regions']),value['unknown_effects'])


def decode(value):
    if value['evidence_format'] not in ('P7-evidence-v1','P7-evidence-v2','P7-evidence-v3','P7-evidence-v4','P7-evidence-v5'):raise ValueError('Unsupported private evidence version')
    legacy=value['evidence_format'] in ('P7-evidence-v1','P7-evidence-v2')
    pre_global=value['evidence_format'] in ('P7-evidence-v1','P7-evidence-v2','P7-evidence-v3')
    bank={}
    for key,payload in value['constraint_recipes'].items():
        item=ConstraintRecipe.wrap(recipe(payload))
        if item.key!=key:raise ValueError('Constraint recipe content hash mismatch')
        bank[key]=item
    def dependency(row):
        checked_keys(TaintDependency,row,('unresolved_constraints','constraint_type') if legacy else ())
        values={key:frozen(item) for key,item in row.items() if key not in ('value','recipes')}
        if row['kind']=='hash':values['value']=TableRoot(**row['value'])
        elif row['kind']=='format_argument':
            checked_keys(DeferredFormatArgument,row['value'])
            values['value']=DeferredFormatArgument(row['value']['format_slot'],row['value']['position'],
                dependency(row['value']['dependency']))
        else:values['value']=frozen(row['value'])
        values['recipes']=tuple(bank[key] for key in row['recipes'])
        return TaintDependency(**values)
    row=value['summary'];checked_keys(TaintProcedureSummary,row,
        (('tables','scalar_returns') if legacy else ())+ (('global_outputs',) if pre_global else ()));sinks=[]
    for sink in row['sinks']:
        checked_keys(SinkRequirement,sink,('destinations','weak_kind','length_dependencies') if legacy else ())
        values={key:frozen(item) for key,item in sink.items() if key not in ('dependencies','destinations','length_dependencies')}
        values['dependencies']=tuple(dependency(dep) for dep in sink['dependencies'])
        values['destinations']=tuple(BufferDestination(**dest) for dest in sink.get('destinations',()))
        if 'length_dependencies' in sink:values['length_dependencies']=tuple(dependency(dep) for dep in sink['length_dependencies'])
        elif legacy:
            rule=lookup(sink['name'])
            if rule is not None and rule.operation=='copy' and rule.lengths:
                values['weak_kind']='copy_length'
                values['length_dependencies']=(TaintDependency('unknown','Historical evidence has no length-taint provenance',uncertain=True),)
        sinks.append(SinkRequirement(**values))
    globals_=None
    if row.get('global_outputs') is not None:
        globals_=[]
        for output in row['global_outputs']:
            checked_keys(GlobalTaintOutput,output)
            globals_.append(GlobalTaintOutput(output['address'],output['width_bits'],Endian(output['endian']),output['span'],output['origin'],
                tuple(dependency(dep) for dep in output['dependencies'])))
        globals_=tuple(globals_)
    return TaintProcedureSummary(row['function'],tuple(dependency(dep) for dep in row['returns']),
        tuple((slot,tuple(dependency(dep) for dep in deps)) for slot,deps in row['outputs']),tuple(sinks),frozen(row['pending']),
        tuple((TableRoot(**root),tuple(dependency(dep) for dep in deps)) for root,deps in row.get('tables',())),
        None if row.get('scalar_returns') is None else tuple(dependency(dep) for dep in row['scalar_returns']),globals_)


def load_latest(folder):
    result={};receipts={};unfinished=[];candidates={}
    for path in sorted(folder.glob('round-*-function-*-result.json')):
        address=int(path.name.split('-function-')[1].split('-result')[0],16)
        candidates.setdefault(address,[]).append(path)
    for address,paths in sorted(candidates.items()):
        for path in reversed(paths):
            try:row=json.loads(path.read_text(encoding='utf8'))
            except json.JSONDecodeError:unfinished.append(str(path));continue
            summary=decode(row)
            if summary.function!=address:raise ValueError('Receipt function identity mismatch')
            result[address]=summary;receipts[address]=path;break
    return result,receipts,unfinished
