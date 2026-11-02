"""Entry state from legacy FastSearch._initial_stack_in_function_start.

The numeric sentinel is a legacy analysis convention, not a concrete runtime
stack address. Object identity is function/context/frame, never the SP name.
Argument roots describe possible pointees and are not proven pairwise disjoint.
"""
from dataclasses import replace
from emtaint.core import MemoryObject, MemoryObjectId
from emtaint.core.contracts import ValueType
from emtaint.memory.access_path import AccessRoot
from emtaint.memory.abstract_heap import ObjectCardinality, ObjectLifetime


def legacy_entry(flow, *, stack_pointer='sp', argument_registers=('r0', 'r1', 'r2', 'r3'), stack_arguments=4):
    if type(stack_arguments) is not int or stack_arguments<0:raise ValueError('Nonnegative stack argument count required')
    p=flow.port
    e=p.engine
    origin=e.origins[0].id
    state=flow.initial()
    scope=p.scope
    stack_id=MemoryObjectId.stack(scope.function, scope.context, 'legacy-entry')
    stack=AccessRoot(stack_id, 'stack', 'default', origin)
    e.add_object(MemoryObject(stack_id, 'Legacy entry frame'), stack, ObjectCardinality.SINGLETON,
                 ObjectLifetime.FRAME, ('Legacy _initial_stack_in_function_start: SP=0x7fffffff',))
    for root in getattr(e, 'segment_roots', ()):
        e.prove_disjoint(stack.object_id, root.object_id, 'Legacy stack convention outside ELF load mappings')
    registers={stack_pointer:p.constant(0x7fffffff, ValueType.bv(e.architecture.pointer_bits), origin)}
    addresses={'reg:'+stack_pointer:(stack, 0)}
    argument_roots={}
    inputs=[]
    for index in range(len(argument_registers)+stack_arguments):
        obj=MemoryObjectId.argument(scope.function, index, scope.context)
        root=AccessRoot(obj, 'argument', 'default', origin)
        e.add_object(MemoryObject(obj, 'Legacy unresolved argument '+str(index)), root,
                     ObjectCardinality.UNKNOWN, ObjectLifetime.EXTERNAL,
                     ('Unresolved function interface; argument pointees can alias',))
        argument_roots[index]=root
        value=p.symbol('argument:'+str(index), ValueType.bv(e.architecture.pointer_bits), origin)
        if index<len(argument_registers):
            name=argument_registers[index]
            registers[name]=value
            addresses['reg:'+name]=(root, 0)
        else:inputs.append(value)
    e.argument_roots=argument_roots
    if e.reads:raise ValueError('Entry input bindings must precede all memory queries')
    e.entry_frame_inputs={stack_id:tuple(inputs)}
    return replace(state, registers=tuple(sorted(registers.items())),
                   addresses=tuple(sorted((*state.addresses, *addresses.items()))))
