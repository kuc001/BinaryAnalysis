"""Strict tagged JSON v1 codec and generated JSON Schemas. No dynamic type imports.

Schemas check shape; constructors also check cross-references and semantic
preconditions. A validated packet is not a proof of heap/analysis correctness.
"""
from dataclasses import fields, is_dataclass
from enum import Enum
import json
from types import MappingProxyType, UnionType
from typing import get_args, get_origin, get_type_hints, Union

from emtaint.core import identity as ids
from emtaint.core import program as core
from emtaint.core import contracts
from emtaint.memory import access_path, state, query_port, abstract_heap
from . import model


def _registry():
    classes = [ids.BinaryId, ids.FunctionId, ids.BlockId, ids.ProgramPoint, ids.CallSiteId,
               ids.ContextId, ids.MemoryObjectId, core.Register, core.Architecture, core.ABI,
               core.MemoryObject]
    enums = [ids.MemoryKind, core.Endian, core.Completeness]
    for module in (contracts, access_path, abstract_heap, state, query_port, model):
        for value in vars(module).values():
            if not isinstance(value, type) or value.__module__ != module.__name__:
                continue
            if is_dataclass(value):
                classes.append(value)
            elif issubclass(value, Enum):
                enums.append(value)
    registry = {cls.__name__: cls for cls in classes + enums}
    if len(registry) != len(classes + enums):
        raise RuntimeError('Duplicate wire type name')
    return MappingProxyType(registry)


REGISTRY = _registry()


def _encode(value, depth, count, max_nodes, max_depth):
    count[0] += 1
    if count[0] > max_nodes or depth > max_depth:
        raise ValueError('Wire encode node/depth budget exceeded')
    if isinstance(value, Enum):
        if REGISTRY.get(type(value).__name__) is not type(value):
            raise TypeError('Unregistered wire enum')
        return {'$enum': type(value).__name__, 'value': value.value}
    if value is None or type(value) in (str, int, bool):
        if type(value) is int and abs(value).bit_length() > 4096:
            raise ValueError('Wire integer exceeds 4096 bits')
        return value
    if type(value) is tuple:
        return [_encode(v, depth + 1, count, max_nodes, max_depth) for v in value]
    if is_dataclass(value) and REGISTRY.get(type(value).__name__) is type(value):
        return {'$type': type(value).__name__, **{
            f.name: _encode(getattr(value, f.name), depth + 1, count, max_nodes, max_depth)
            for f in fields(value) if f.init}}
    raise TypeError('Only registered immutable contract types can cross the wire')


def dumps(
    record: object,
    *,
    max_nodes: int = 100000,
    max_depth: int = 64,
    max_bytes: int = 16 * 1024 * 1024,
) -> str:
    """Encode one registered immutable contract record as bounded tagged JSON."""

    if not is_dataclass(record) or isinstance(record, type):
        raise TypeError('Wire root must be a registered contract record')
    value = _encode(record, 0, [0], max_nodes, max_depth)
    result = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(',', ':'), allow_nan=False)
    if len(result.encode('utf8')) > max_bytes:
        raise ValueError('Wire encode byte budget exceeded')
    return result


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('Duplicate JSON key: ' + key)
        result[key] = value
    return result


def _no_float(value):
    raise ValueError('Wire v1 has no floating-point JSON values: ' + value)


def _int(value):
    result = int(value)
    if abs(result).bit_length() > 4096:
        raise ValueError('Wire integer exceeds 4096 bits')
    return result


def _decode(value, depth, count, max_nodes, max_depth):
    count[0] += 1
    if count[0] > max_nodes or depth > max_depth:
        raise ValueError('Wire decode node/depth budget exceeded')
    if type(value) is list:
        return tuple(_decode(v, depth + 1, count, max_nodes, max_depth) for v in value)
    if type(value) is not dict:
        return value
    if '$enum' in value:
        cls = REGISTRY.get(value['$enum']) if type(value['$enum']) is str else None
        if set(value) != {'$enum', 'value'} or cls is None or not issubclass(cls, Enum):
            raise ValueError('Unknown enum or unexpected enum fields')
        return cls(value['value'])
    cls = REGISTRY.get(value.get('$type')) if type(value.get('$type')) is str else None
    if cls is None or not is_dataclass(cls):
        raise ValueError('Unknown record type; dynamic imports are forbidden')
    expected = {f.name for f in fields(cls) if f.init}
    if set(value) != expected | {'$type'}:
        raise ValueError('Missing or unexpected fields for ' + cls.__name__)
    kwargs = {name: _decode(value[name], depth + 1, count, max_nodes, max_depth) for name in expected}
    hints = contracts.record_annotations(cls)
    if any(not contracts.check_type(v, hints[name]) for name, v in kwargs.items()):
        raise TypeError('Wire field sort mismatch in ' + cls.__name__)
    return cls(**kwargs)


def loads(
    payload: str,
    *,
    max_nodes: int = 100000,
    max_depth: int = 64,
    max_bytes: int = 16 * 1024 * 1024,
) -> object:
    """Decode bounded tagged JSON into a registered immutable contract record.

    The concrete return type is selected by the closed wire tag registry; no
    dynamic import or caller-provided class resolution is performed.
    """

    if type(payload) is not str:
        raise TypeError('Wire decoder needs UTF-8 JSON text')
    if len(payload.encode('utf8')) > max_bytes:
        raise ValueError('Wire decode byte budget exceeded')
    try:
        parsed = json.loads(payload, object_pairs_hook=_pairs, parse_constant=_no_float,
                            parse_float=_no_float, parse_int=_int)
    except RecursionError as error:
        raise ValueError('JSON nesting exceeds parser limits') from error
    result = _decode(parsed, 0, [0], max_nodes, max_depth)
    if not is_dataclass(result) or isinstance(result, type):
        raise ValueError('Wire root must be a contract record')
    return result


def _shape(annotation):
    origin, args = get_origin(annotation), get_args(annotation)
    if origin in (Union, UnionType):
        return {'anyOf': [_shape(arg) for arg in args]}
    if annotation is type(None):
        return {'type': 'null'}
    if annotation in (str, int, bool):
        return {'type': {str: 'string', int: 'integer', bool: 'boolean'}[annotation]}
    if origin is tuple or annotation is tuple:
        if not args:
            return {'type': 'array', 'items': {'anyOf': [{'type': 'string'}, {'type': 'integer'}]}}
        if len(args) == 2 and args[1] is Ellipsis:
            return {'type': 'array', 'items': _shape(args[0])}
        return {'type': 'array', 'prefixItems': [_shape(arg) for arg in args],
                'minItems': len(args), 'maxItems': len(args)}
    if isinstance(annotation, type) and REGISTRY.get(annotation.__name__) is annotation:
        return {'$ref': '#/$defs/' + annotation.__name__}
    raise TypeError('Unspecified wire field schema: ' + str(annotation))


def schema_documents() -> dict[str, dict[str, object]]:
    """Build JSON Schema documents for the current CIR and memory wire roots."""

    definitions = {}
    for name, cls in REGISTRY.items():
        if issubclass(cls, Enum):
            properties = {'$enum': {'const': name}, 'value': {'enum': [v.value for v in cls]}}
        else:
            hints = get_type_hints(cls)
            properties = {'$type': {'const': name}, **{
                f.name: _shape(hints[f.name]) for f in fields(cls) if f.init}}
            if cls == model.CIRModule:
                properties['schema_version'] = {'const': contracts.CIR_VERSION}
                properties['memory_semantics_version'] = {'const': contracts.MEMORY_VERSION}
                properties['capabilities'] = {'type': 'array', 'uniqueItems': True,
                                               'items': {'enum': sorted(model.CAPABILITIES)}}
            elif cls == state.MemorySnapshot:
                properties['schema_version'] = {'const': contracts.MEMORY_VERSION}
        definitions[name] = {'type': 'object', 'properties': properties,
                             'required': list(properties), 'additionalProperties': False}
    return {file: {'$schema': 'https://json-schema.org/draft/2020-12/schema',
                   '$id': 'urn:emtaint:' + version, 'title': version,
                   '$ref': '#/$defs/' + root, '$defs': definitions}
            for file, version, root in (
                ('cir-wire-v1.json', contracts.CIR_VERSION, 'CIRModule'),
                ('memory-semantics-v1.json', contracts.MEMORY_VERSION, 'MemorySnapshot'))}
