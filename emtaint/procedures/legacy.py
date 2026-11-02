"""Old libc taint semantics, not concrete libc execution or new sink rules."""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class ProcedureRule:
    """Exact legacy procedure branch, with a stable name-based rule identity."""

    name:str
    operation:str
    destination:int|None=None
    source:int|None=None
    lengths:tuple=()
    format_index:int|None=None
    variadic_start:int|None=None
    constraint_type:int=0
    returns_file_handle:bool=False
    provenance:str=''

    @property
    def rule_id(self)->str:
        """Keep identity stable when a rule's transfer implementation changes."""
        return 'legacy-procedure/'+self.name


def rule(name:str, operation:str, **kwargs)->ProcedureRule:
    return ProcedureRule(name, operation, provenance='Legacy dataflow/procedures/libc/'+name+'.py', **kwargs)


RULES=tuple(
    [rule(n, 'source_buffer', destination=1, source=0, lengths=(2,)) for n in ('BIO_read', 'recv', 'recvfrom', 'read')]+
    [rule('fgets', 'source_buffer', destination=0, source=2, lengths=(1,)),
     rule('fread', 'source_buffer', destination=0, source=3, lengths=(1, 2)),
     rule('getenv', 'source_return', source=0),
     ProcedureRule('FCGX_GetParam', 'source_return', source=0,
         provenance='Legacy dataflow/procedures/libcustomize/FCGX_GetParam.py:run; registered but absent from default custom_sources'),
     ProcedureRule('hdf_get_value', 'source_return', source=1,
         provenance='Legacy dataflow/procedures/libcustomize/hdf_get_value.py:run; registered but absent from default custom_sources'),
     rule('BIO_gets', 'source_buffer', destination=1, source=0, lengths=(2,))]+
    [rule(n, 'copy', destination=0, source=1) for n in ('strcpy', 'strcat')]+
    [rule(n, 'copy', destination=0, source=1, lengths=(2,)) for n in ('strncpy', 'strncat', 'strlcpy', 'memcpy', 'memmove')]+
    [rule(n, 'return_alias', source=0) for n in ('strstr', 'strchr', 'strrchr', 'strdup', 'strpbrk')]+
    [rule('strtok', 'stateful_token', source=0), ProcedureRule('SSL_read', 'legacy_trace_source',
        destination=1, source=0, lengths=(2,),
        provenance='Legacy dataflow/procedures/libssl/SSL_read.py:run -> dataflow/data_process.py:inital_source_arguments; backward 0x100 trace without taint_source ID')]+
    [rule('strsep', 'deref_return', source=0)]+
    [rule('hsearch_r', 'hash_search', source=1, destination=3)]+
    [rule(n, 'integer_return', source=0, constraint_type=kind) for n, kind in (
        ('atoi', 4), ('atol', 4), ('atoll', 4), ('strtol', 4), ('strtoll', 4), ('strtoul', 4), ('strlen', 5))]+
    [rule(n, 'constraint', source=0, constraint_type=2) for n in ('strcmp', 'strcasecmp', 'stricmp')]+
    [rule('inet_pton', 'constraint', source=1, constraint_type=1)]+
    [rule(n, 'constraint', source=0, constraint_type=1) for n in ('inet_aton', 'gethostbyname', 'gethostbyname2')]+
    [rule('fopen', 'file_handle', returns_file_handle=True),
     rule('fdopen', 'file_handle', source=0, returns_file_handle=True),
     rule('accept', 'socket_handle')]+
    [rule(n, 'legacy_noop') for n in ('strncmp', 'strncasecmp')]+
    [rule('sprintf', 'format_output', destination=0, format_index=1, variadic_start=2),
     rule('snprintf', 'format_output', destination=0, lengths=(1,), format_index=2, variadic_start=3),
     ProcedureRule('vsnprintf', 'format_output_va_list', destination=0, source=3, lengths=(1,), format_index=2,
         provenance='Legacy dataflow/procedures/libc/vsnprintf.py:run -> format_parser.py:_find_taint_propagate_in_format_v4; va_list Store offset modulo arch.bytes selects string format arguments'),
     rule('sscanf', 'format_input', source=0, format_index=1, variadic_start=2)]+
    [rule('system', 'command', source=0),
     rule('popen', 'command', source=0, returns_file_handle=True)]+
    [rule('_system', 'command', source=0, format_index=0, variadic_start=1)]+
    [rule('execve', 'command_argv', source=1)])


RULES_BY_NAME={rule.name:rule for rule in RULES}
if len(RULES_BY_NAME)!=len(RULES):
    raise ValueError('Duplicate legacy procedure rule')


def lookup(name:str)->ProcedureRule|None:
    """Match the exact symbol used by the old procedure dispatch."""
    return RULES_BY_NAME.get(name)


def legacy_copy_weak_kind(*, bounded, buffer_tainted, length_tainted):
    """Actual reg_taint_propagate taint_loc/0x1000 + Collector marking.

    None is an unproved input, never evidence that a bounded copy is safe.
    Propagation through the copy is separate from marking a legacy weak site.
    """
    if buffer_tainted is False:return None
    if buffer_tainted is None:return 'unknown'
    if not bounded:return 'copy'
    if length_tainted is None:return 'unknown'
    return 'copy_length' if length_tainted else None


def legacy_copy_length_constraints(rows):
    """Old _calculate_copy_lenght_constraint: only Cons type 4 contributes."""
    values=[]
    for kind, constraints in rows:
        if kind!=4:continue
        numbers=[value for value in constraints if type(value) is int and value!=0]
        if numbers:values.append(min(numbers))
    return tuple(dict.fromkeys(values))


def uniform_copy_length_constraints(dependencies):
    """A bound from one path cannot cap a different possible length.

    The old per-trace helper above remains available for an individual trace.
    A joined P7 demand may contain distinct sources or an unknown branch;
    only one distinct, fully bounded scalar origin supplies a shared bound.
    """
    alternatives=tuple(dict.fromkeys(dependency for dependency in dependencies
        if dependency.kind in ('source', 'argument', 'scalar_argument', 'unknown')))
    if len(alternatives)!=1 or alternatives[0].kind not in ('source', 'argument'):
        return ()
    dependency=alternatives[0]
    return legacy_copy_length_constraints(((dependency.constraint_type, dependency.constraints),))


def legacy_format_parameters(data):
    """Exact _find_fmt_parameters/_match_spec_v2 classification.

    Old rules do not fully implement printf/scanf. Keep this legacy descriptor
    for comparison; callers must retain unknown semantics for unsupported C
    formats instead of interpreting the descriptor as a sanitizer proof.
    """
    if type(data) is not bytes:raise TypeError('Concrete bytes required for legacy format descriptor')
    args=[]
    for index, value in enumerate(data):
        if value!=37:continue
        i=index+1
        while i<len(data) and 48<=data[i]<=57:i+=1
        if i==len(data):continue
        if data[i] in (115, 91, 123):args.append('s')
        elif data[i]!=42:args.append('i')
    return tuple(args)


def legacy_integer_constraints(constraints):
    """SimProcedure._calculate_atoi_constraint decimal-length heuristic."""
    values=[value for value in constraints if type(value) is int and value!=0]
    minimum=min(values) if values else None
    if minimum is not None and 0<=minimum<8:return (10**minimum-1,)
    return tuple(constraints)
