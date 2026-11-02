"""CIR ports of old backward use/def and procedure taint requirements.

Dependencies are detached source/argument/global descriptors. Memory alias
decisions stay in MemoryQueryPort; unknown correspondence remains explicit.
This pass produces may-flow requirements, not concrete vulnerability proofs.
"""
from dataclasses import dataclass, replace, field
from collections import Counter, deque
import hashlib
import time
import traceback
from emtaint.core import BlockId, MemoryObject, MemoryObjectId
from emtaint.core.contracts import Constant, ValueRef, ValueType
from emtaint.ir.canonical import (Compute, ReadRegister, RegisterSlice, WriteRegister, LoadEffect, StoreEffect,
    CallEffect, DirectTarget, ExternalTarget, ReturnEffect, UnknownEffect, BranchEffect, JumpEffect)
from emtaint.memory import SymbolicOp, AccessRoot, AliasKind
from emtaint.memory.state import MemoryLocation
from emtaint.memory.abstract_heap import ObjectCardinality, ObjectLifetime
from emtaint.analysis.dataflow.legacy_demand import LegacyDemand, DemandBudget, DemandLimit, ArgumentRead
from emtaint.analysis.taint.regions import RegionTaintTracker
from emtaint.procedures.legacy import ProcedureRule, lookup, legacy_format_parameters
from emtaint.memory.policies import BudgetExceeded
from emtaint.analysis.taint.guards import legacy_constraint, arm_unsigned_hi, arm_zero_flag_equal, unit_product_arguments
from emtaint.analysis.framework.summaries import compile_recipe
from emtaint.procedures.legacy import legacy_integer_constraints, uniform_copy_length_constraints
from emtaint.analysis.taint.tables import LegacyHashTables
from emtaint.analysis.taint.subsumption import source_antichain
from emtaint.analysis.taint.definition_frontier import DefinitionFrontierCache
from emtaint.analysis.taint.global_outputs import output_order as global_output_order, location as global_output_location
from emtaint.analysis.taint.facts import ScalarTaintFact


@dataclass(frozen=True)
class ConstraintRecipe:
    key:str
    value:object=field(compare=False, hash=False, repr=False)

    @classmethod
    def wrap(cls, value):
        return cls(hashlib.sha256(repr(value).encode('utf8')).hexdigest(), value)


@dataclass(frozen=True)
class TaintDependency:
    kind:str
    value:object
    constraints:tuple=()
    # Paths remain part of dependency identity until source_antichain records
    # an explicit covered->covering relation. Ignoring them in dataclass
    # equality silently discards alternate caller chains before that evidence
    # hook can observe them. The antichain itself excludes path from its
    # semantic key, so equivalent Source paths do not multiply propagation.
    path:tuple=field(default=())
    uncertain:bool=False
    guards:tuple=()
    handles:tuple=()
    offset:int|None=0
    recipes:tuple=()
    access_width:int=8
    byte_access:bool=False
    unresolved_constraints:bool=False
    constraint_type:int=0


@dataclass(frozen=True)
class DeferredFormatArgument:
    """A va_list candidate selected only after a caller supplies the format.

    ``format_slot`` belongs to the current detached procedure signature;
    ``position`` is the legacy FormatParser parameter index.  The nested
    dependency remains detached as well, so no caller-scoped SSE/APG identity
    crosses the summary boundary.
    """
    format_slot:int
    position:int
    dependency:TaintDependency


@dataclass(frozen=True)
class BufferDestination:
    kind:str
    value:object
    offset:int|None=0


@dataclass(frozen=True)
class SinkRequirement:
    function:int
    site:int
    name:str
    kind:str
    offsets:tuple
    dependencies:tuple
    origin:str
    constraints:tuple=()
    guards:tuple=()
    destinations:tuple=()
    weak_kind:str='copy'
    length_dependencies:tuple=()


@dataclass(frozen=True)
class TaintProcedureSummary:
    function:int
    returns:tuple=()
    outputs:tuple=()
    sinks:tuple=()
    pending:tuple=()
    tables:tuple=()
    scalar_returns:tuple|None=None
    global_outputs:tuple|None=None


def dependency_order(dep):
    return dep.kind, repr(dep.value), repr(dep.constraints), dep.uncertain, repr(dep.guards), repr(dep.handles), repr(dep.offset), repr(dep.recipes), dep.access_width, dep.byte_access, dep.unresolved_constraints, dep.constraint_type


def sink_order(sink):
    return sink.function, sink.site, sink.name, sink.kind, repr(sink.offsets), sink.origin, repr(sink.constraints), repr(sink.guards), repr(sink.destinations), sink.weak_kind


class ProcedureDemand(LegacyDemand):
    def __init__(self, *args, names=None, cache_queries=True, **kwargs):
        self.reaching_cache={}
        self.definition_cache={}
        self.recurrence_cache={}
        self.recurrence_cache_hits=0
        self.query_scalar_limit=None
        super().__init__(*args, **kwargs)
        self.names=dict(names or {})
        self.return_calls={}
        self.cache_queries=cache_queries
        self.binding_cache={}
        self.frontiers=DefinitionFrontierCache(self)
        self.predecessors={block:tuple(sorted(values, key=lambda b:(b.rva, b.index, b.mode))) for block, values in self.predecessors.items()}

    def guard_concrete(self, reference):return self.port.guard_concrete(reference)

    def tick(self, depth):
        super().tick(depth)
        if self.query_scalar_limit is not None and self.steps>self.query_scalar_limit:
            raise DemandLimit('Independent scalar query share exhausted', dimension='query')

    def reaching(self, block, index, name):
        key=block, index, name
        if self.cache_queries and key in self.reaching_cache:
            self.tick(0)
            return self.reaching_cache[key]
        definitions, entry=super().reaching(block, index, name)
        result=frozenset(definitions), entry
        if self.cache_queries:self.reaching_cache[key]=result
        return result

    def register(self, block, index, name, width, depth):
        # The old recurrence transfer already leaves a symbolic remainder
        # when a loop is non-affine. At one immutable CFG cutoff that is one
        # abstract register value, so subsequent independent P7 demands can
        # reuse its completed result. Never retain a value referring to an
        # outer register demand still active during its construction.
        cutoff=self.definition_cutoff(block, index, name)
        key=block, cutoff, name, width
        if self.cache_queries and key in self.recurrence_cache:
            self.tick(depth)
            self.recurrence_cache_hits+=1
            return self.recurrence_cache[key]
        outer=frozenset(self.active.values())
        result=super().register(block, index, name, width, depth)
        base_key=('reg', block, cutoff, name)
        if (self.cache_queries and base_key not in self.memo and len(self.recurrence_cache)<4096
                and not any(self.contains(value, outer) for value in result)):
            self.recurrence_cache[key]=result
        return result

    def memory_definitions(self, block, index, loc, load, seen, depth):
        if not self.cache_queries or self.summaries:
            return super().memory_definitions(block, index, loc, load, seen, depth)
        e=self.port.engine
        key=(block, index, loc.id.scope, loc.object_id, loc.offset_lower, loc.offset_upper, loc.width_bits,
            loc.endian, loc.address_space, loc.origin, loc.assessment, load.origin, load.width_bits, load.endian,
            self.initial.memory, tuple(e.object_facts.items()))
        if key in self.definition_cache:
            self.tick(depth)
            return self.definition_cache[key]
        result=self.frontiers.query(block, index, loc, load, seen, depth)
        if len(self.definition_cache)<8192 and not any(self.contains(value, self.cycles) for value in result[0]):self.definition_cache[key]=result
        return result

    def address_binding(self, reference, seen=frozenset()):
        if not self.cache_queries or seen:return super().address_binding(reference, seen)
        if reference not in self.binding_cache:self.binding_cache[reference]=super().address_binding(reference, seen)
        return self.binding_cache[reference]

    def exact_stack_address(
            self, operand: Constant | ValueRef, seen: frozenset[str] = frozenset()
    ) -> tuple[AccessRoot, int | None] | None:
        """Project a copied constant offset from an unchanged entry SP for an exact stack query."""
        if hasattr(operand, 'id') and operand.id not in seen and operand.id in self.defs:
            block, index, effect=self.defs[operand.id]
            if isinstance(effect, ReadRegister):
                name=effect.source.register
                definitions, entry=self.reaching(block, index, name)
                if name=='sp' and self.stack_proven and not definitions and entry:
                    return dict(self.initial.addresses).get('reg:sp')
                if len(definitions)==1 and not entry:
                    defined_block, cutoff=next(iter(definitions))
                    prior=self.blocks[defined_block].effects[cutoff-1]
                    if (isinstance(prior, WriteRegister) and prior.target.register==name
                            and prior.target.bit_offset==0 and prior.target.width_bits==prior.target.register_width_bits
                            and getattr(prior.guard, 'value', None) is True):
                        return self.exact_stack_address(prior.value, seen|{operand.id})
                return None
            if isinstance(effect, Compute) and effect.op.value=='copy':
                return self.exact_stack_address(effect.args[0], seen|{operand.id})
            if isinstance(effect, Compute) and effect.op.value in ('add', 'sub'):
                if effect.op.value=='add' and self.literal(effect.args[0])==0:
                    return self.exact_stack_address(effect.args[1], seen|{operand.id})
                delta=self.literal(effect.args[1])
                if type(delta) is int:
                    base=self.exact_stack_address(effect.args[0], seen|{operand.id})
                    if base is not None:
                        root, offset=base
                        if offset is None:return root, None
                        width=self.port.engine.architecture.pointer_bits
                        return root, (offset+(delta if effect.op.value=='add' else -delta))%(1<<width)
        return super().local_address(operand, seen) if isinstance(operand, Constant) else None

    def call_name(self, call):
        return self.names.get(call.site.point.instruction_rva, call.target.symbol if isinstance(call.target, ExternalTarget) else '')

    def exact_slice_before(self, block:BlockId, index:int, source:RegisterSlice,
                           depth:int, seen:frozenset=frozenset())->tuple:
        """Follow only full-coverage slice definitions; preserve each CFG alternative.

        An overlapping write with different geometry falls back to Unknown.
        This P7 refinement leaves P6 whole-register demand unchanged.
        """
        key=block, index, source
        if key in seen:
            return self.port.unknown(ValueType.bv(source.width_bits),
                self.blocks[block].effects[0].origin, 'Cyclic partial register demand'),
        seen=seen|{key}
        definitions, entry=self.reaching(block, index, source.register)
        if definitions:
            alternatives=[]
            for defined_block, cutoff in sorted(definitions,
                    key=lambda item:(item[0].rva, item[0].index, item[0].mode, item[1])):
                alternatives.append(self.exact_slice_definition(
                    defined_block, cutoff, source, depth+1, seen))
            if entry:alternatives.append(self.full_slice_fallback(block, index, source, depth+1))
            return self.union(alternatives)
        return self.full_slice_fallback(block, index, source, depth+1)

    def exact_slice_definition(self, block:BlockId, cutoff:int, source:RegisterSlice,
                               depth:int, seen:frozenset)->tuple:
        write=self.blocks[block].effects[cutoff-1]
        if isinstance(write, WriteRegister):
            target=write.target
            if (target.bit_offset+target.width_bits<=source.bit_offset or
                    source.bit_offset+source.width_bits<=target.bit_offset):
                return self.exact_slice_before(block, cutoff-1, source, depth+1, seen)
            if target==source:
                guards=self.value(write.guard, depth+1)
                choices={self.guard_concrete(guard) for guard in guards}
                written=self.value(write.value, depth+1) if choices!={False} else ()
                if choices=={True}:
                    self.rules.add('p7.exact-partial-register-slice')
                    return written
                previous=self.exact_slice_before(block, cutoff-1, source, depth+1, seen)
                self.rules.add('p7.conditional-partial-register-slice')
                return self.union((written, previous))
        return self.full_slice_fallback(block, cutoff, source, depth+1)

    def full_slice_fallback(self, block:BlockId, index:int, source:RegisterSlice,
                            depth:int)->tuple:
        full=self.register(block, index, source.register,
                           source.register_width_bits, depth+1)
        return tuple(self.port.operation(SymbolicOp.EXTRACT, ValueType.bv(source.width_bits),
            (value,), self.blocks[block].effects[0].origin,
            (source.bit_offset+source.width_bits-1, source.bit_offset)) for value in full)

    def value(self, operand, depth=0):
        definition=self.defs.get(operand.id) if hasattr(operand, 'id') else None
        if definition and isinstance(definition[2], ReadRegister):
            block, index, effect=definition
            source=effect.source
            if source.width_bits!=source.register_width_bits or source.bit_offset:
                return self.exact_slice_before(block, index, source, depth)
        if definition and isinstance(definition[2], CallEffect):
            call=definition[2]
            key='procedure-return:'+call.origin
            self.return_calls[key]=call
            unresolved=self.port.symbol(key, operand.type, call.origin)
            # The old strstr procedure propagates the haystack pointer to
            # its return. Keep the unresolved alternative for no match or an
            # interior pointer; actual haystack values still matter when the
            # return is later used as a copy destination.
            if (self.call_name(call)=='strstr' and call.arguments
                    and getattr(call.guard, 'value', None) is not False):
                return tuple(dict.fromkeys((unresolved,)+self.value(call.arguments[0], depth+1)))
            return (unresolved,)
        return super().value(operand, depth)


class LegacyTaintDemand:
    def __init__(self, function, port, cfg, initial, *, names=None, summaries=None, targets=None, image_base=0,
                 max_steps=250000, max_dependencies=256, cache_queries=True, tables=None, function_deadline=None):
        self.function=function
        self.port=port
        self.cfg=cfg
        self.base=image_base
        self.demand=ProcedureDemand(function, port, cfg, initial, budget=DemandBudget(steps=500000, alternatives=256, depth=120), names=names, cache_queries=cache_queries)
        self.summaries=summaries or {}
        self.targets=targets or {}
        self.steps=0
        self.max_steps=max_steps
        self.max_dependencies=max_dependencies
        self.memo={}
        self.active=set()
        self.pending=[]
        self.diagnostics=[]
        self.regions=RegionTaintTracker(port)
        self.source_bindings={}
        self.unknown_roots={}
        self.scalar_source_facts={}
        self.format_cache={}
        self.format_descriptor_cache={}
        self.expression_cache={}
        self.expression_active=set()
        self.completed_sinks=[]
        self.completed_returns=[]
        self.completed_outputs={}
        self.frontier=None
        self.completed_scalar_returns=[]
        self.scalar_cache={}
        self.scalar_active=set()
        self.completed_global_outputs={}
        self.active_global_output=None
        self.alternative_overflows=[]
        self.local_recoveries=[]
        self.va_list_diagnostics=[]
        self.sink_indices={}
        self.edge_policy_cache={}
        self.path_guard_cache={}
        self.path_guard_operands={}
        self.guarded_length_cache={}
        self.transfer_length_failures=set()
        self.imported_bindings={}
        self.cache_queries=cache_queries
        self.argument_cache={}
        self.location_cache={}
        self.recipe_cache={}
        self.unresolved_recipe_calls=set()
        self.unknown_evidence=set()
        self.active_sink=None
        self.partial_sources=set()
        self.covered_sources=set()
        self.query_step_limit=None
        self.queries_remaining=1
        self.query_work_limit=None
        self.query_clock_limit=None
        self.function_deadline=function_deadline
        self.function_started=time.monotonic()
        self.query_pending={}
        self.query_history=[]
        self.current_query=None
        self.query_sources=set()
        self.argument_preparations=[]
        self.bound_recipe_cache={}
        self.table_state=LegacyHashTables(self, tables or {})
        self.calls={e.origin:(b.id, i, e) for b in function.blocks for i, e in enumerate(b.effects) if isinstance(e, CallEffect)}
        self.load_positions={e.origin:(b.id, i) for b in function.blocks for i, e in enumerate(b.effects) if isinstance(e, LoadEffect)}
        local_operations=('copy', 'format_output', 'format_input', 'command', 'command_argv')
        self.local_sink_call_count=sum(bool(rule and rule.operation in local_operations)
            for _, _, call in self.calls.values() for rule in (lookup(self.demand.call_name(call)),))
        self.inherited_sink_count=sum(len(self.summaries[callee].sinks)
            for _, _, call in self.calls.values() for callee in self.call_functions(call) if callee in self.summaries)

    def tick(self):
        self.port.validate_current()
        self.steps+=1
        if self.steps>self.max_steps:raise DemandLimit('Taint requirement worklist budget; unresolved dependencies remain')
        if self.query_step_limit is not None and self.steps>self.query_step_limit:
            raise DemandLimit('Independent taint query share exhausted; later queries retain remaining global budget', dimension='query')

    def begin_query(self, query=None):
        remaining=max(1, self.queries_remaining)
        share=max(1, min(self.max_dependencies*4, self.max_steps//16), (self.max_steps-self.steps)//remaining)
        self.queries_remaining=max(0, self.queries_remaining-1)
        self.query_step_limit=self.steps+share
        d=self.demand
        d.query_scalar_limit=d.steps+max(1, d.budget.steps//16, (d.budget.steps-d.steps)//remaining)
        small_local_pool=False
        if query is not None and query.kind=='call' and not self.inherited_sink_count and 0<self.local_sink_call_count<=8:
            rule=lookup(self.demand.call_name(query.effect))
            small_local_pool=bool(rule and rule.operation in ('copy', 'format_output', 'format_input', 'command', 'command_argv'))
            if small_local_pool:
                self.query_step_limit=max(self.query_step_limit, self.steps+min(
                    self.max_steps//8, (self.max_steps-self.steps)//self.local_sink_call_count))
                d.query_scalar_limit=max(d.query_scalar_limit, d.steps+min(
                    d.budget.steps//4, (d.budget.steps-d.steps)//self.local_sink_call_count))
        accounting=self.port.engine.accounting
        used=accounting.counts['worklist_iterations']
        # A sink demand performs many primitive MemoryQueryPort operations.
        # The port's per-operation cap is not this whole demand's allowance.
        self.query_work_limit=used+max(1, accounting.budgets.worklist_iterations//16,
            (accounting.budgets.worklist_iterations-used)//remaining)
        if self.function_deadline is not None:
            now=time.monotonic()
            minimum=max(0, (self.function_deadline-self.function_started)/16)
            if query is not None and query.kind=='call':
                rule=lookup(self.demand.call_name(query.effect))
                if rule and rule.operation in ('copy', 'format_output', 'format_input', 'command', 'command_argv'):
                    minimum=max(minimum, (self.function_deadline-self.function_started)/3)
            self.query_clock_limit=now+max(minimum, (self.function_deadline-now)/remaining)
            if small_local_pool:self.query_clock_limit=self.function_deadline

    def clear_query_limits(self):
        self.query_step_limit=None
        self.query_work_limit=None
        self.query_clock_limit=None
        self.demand.query_scalar_limit=None

    def check_query_clock(self):
        if self.query_clock_limit is not None and time.monotonic()>self.query_clock_limit:
            raise DemandLimit('Independent query wall share exhausted', dimension='query')

    def observe_sources(self, dependencies):
        sources={dependency for dependency in dependencies if dependency.kind=='source'}
        self.query_sources.update(sources)
        if self.active_sink is not None:self.partial_sources.update(sources)

    def union(self, groups):
        def members():
            for group in groups:
                for dependency in group:
                    if dependency.kind=='unknown':
                        # Unknown is the taint-domain upper bound, not a
                        # distinct value for every transitive error string.
                        # Preserve all reasons in the function's evidence
                        # journal while joining the abstract fact itself.
                        self.unknown_evidence.add(str(dependency.value))
                        dependency=replace(dependency, value='Taint correspondence unknown')
                    yield dependency
        # Source paths must reach the antichain callback before dataclass
        # equality collapses them.  Non-Source duplicates (especially joined
        # Unknown reasons) are still removed after that explicit evidence
        # relation has been recorded.
        reduced=source_antichain(members(),
            lambda narrow, broad:self.covered_sources.add((narrow, broad)))
        result=tuple(sorted(dict.fromkeys(reduced), key=dependency_order))
        self.observe_sources(result)
        if len(result)>self.max_dependencies:
            self.alternative_overflows.append({
                'frontier':self.frontier,
                'active_sink':None if self.active_sink is None else self.active_sink.origin,
                'total':len(result),
                'kinds':dict(sorted(Counter(dependency.kind for dependency in result).items())),
                'source_sites':dict(sorted(Counter(str(dependency.value) for dependency in result
                    if dependency.kind=='source').items(), key=lambda item:(-item[1], item[0]))[:16]),
                'source_guard_counts':dict(sorted(Counter(len(dependency.guards) for dependency in result
                    if dependency.kind=='source').items())),
                'source_recipe_counts':dict(sorted(Counter(len(dependency.recipes) for dependency in result
                    if dependency.kind=='source').items())),
                'source_path_counts':dict(sorted(Counter(len(dependency.path) for dependency in result
                    if dependency.kind=='source').items())),
                'query_sources_after_observe':len(self.query_sources),
                'partial_sources_after_observe':len(self.partial_sources),
                'stack':tuple(frame.name+':'+str(frame.lineno) for frame in traceback.extract_stack(limit=8)[:-1]),
            })
            raise DemandLimit('Taint dependency alternatives budget; no empty-flow conclusion', dimension='alternatives')
        return result

    def argument(self, call, index):
        key=call.origin, index
        if not self.cache_queries:return self.argument_query(call, index)
        if key not in self.argument_cache:self.argument_cache[key]=self.argument_query(call, index)
        return self.argument_cache[key]

    def argument_query(self, call, index):
        # A call's SSA argument is shared by every inherited demand at that
        # actual callsite. Resolve it once under the unchanged function-global
        # caps. Truncating it under each sink's tiny share repeatedly rebuilds
        # the same prefix and never produces a reusable argument value.
        shared=self.current_query is not None
        scalar=self.demand.steps
        work=self.port.engine.accounting.counts['worklist_iterations']
        started=time.monotonic()
        limits=(self.demand.query_scalar_limit, self.query_work_limit, self.query_clock_limit)
        if shared:self.demand.query_scalar_limit=self.query_work_limit=self.query_clock_limit=None
        status='complete'
        try:return self._argument(call, index)
        except DemandLimit as error:
            status='incomplete'
            if error.dimension=='query':raise
            self.local_failure(error, call.origin)
            type_=call.arguments[index].type if index<len(call.arguments) else ValueType.bv(self.port.engine.architecture.pointer_bits)
            return (self.port.unknown(type_, call.origin, 'Unresolved call argument '+str(index)+': '+str(error)),)
        except (BudgetExceeded, RecursionError):
            status='incomplete'
            raise
        finally:
            if shared:
                scalar_cost=self.demand.steps-scalar
                work_cost=self.port.engine.accounting.counts['worklist_iterations']-work
                seconds=time.monotonic()-started
                self.demand.query_scalar_limit=None if limits[0] is None else limits[0]+scalar_cost
                self.query_work_limit=None if limits[1] is None else limits[1]+work_cost
                self.query_clock_limit=None if limits[2] is None else limits[2]+seconds
                self.argument_preparations.append({'origin':call.origin, 'slot':index, 'scalar_steps':scalar_cost,
                    'memory_work':work_cost, 'seconds':seconds, 'status':status})

    def _argument(self, call, index):
        if index<len(call.arguments):return self.demand.value(call.arguments[index])
        count=len(call.abi.argument_registers or ('r0', 'r1', 'r2', 'r3'))
        if index<count:return (self.port.unknown(ValueType.bv(self.port.engine.architecture.pointer_bits), call.origin, 'Unavailable call argument'),)
        return self.demand.stack_argument(call, index-count, self.port.engine.architecture.pointer_bits, 0)

    def location(self, reference, origin):
        key=reference, origin
        if not self.cache_queries:return self._location(reference, origin)
        if key not in self.location_cache:self.location_cache[key]=self._location(reference, origin)
        return self.location_cache[key]

    def _location(self, reference, origin):
        engine=self.port.engine
        binding=self.demand.address_binding(reference)
        return engine.location(*binding, 8, engine.architecture.endian, origin) if binding else engine.location(None, None, 8, engine.architecture.endian, origin)

    def constants(self, call, indices):
        groups=[{self.demand.guard_concrete(v) for v in self.argument(call, i)} for i in indices]
        if not groups:return ()
        if all(len(g)==1 and type(next(iter(g))) is int for g in groups):
            value=1
            for group in groups:value*=next(iter(group))
            return (value,)
        return ()

    def procedure_region(self, call, rule, reference):
        p=self.port
        e=p.engine
        binding=self.demand.address_binding(reference)
        lengths=self.constants(call, rule.lengths)
        if lengths==(0,):return None
        if binding:
            root, offset=binding
            if offset is not None and lengths and 0<lengths[0] and offset+lengths[0]<(1<<e.architecture.pointer_bits):
                return e.location(root, offset, 8, e.architecture.endian, call.origin, upper=offset+lengths[0]-1)
            return e.location(root, None, 8, e.architecture.endian, call.origin)
        return e.location(None, None, 8, e.architecture.endian, call.origin)

    def path_guards(self, call):
        """Retain recognized guards on every resolved CIR path to a call.

        A unique unconditional jump can remove an imported speculative edge.
        An incomplete CFG still makes these observations conditional evidence,
        never an UNSAT result or a clean-source proof.
        """
        if call.origin in self.path_guard_cache:return self.path_guard_cache[call.origin]
        cfg=self.cfg
        destination=call.site.point.block
        if cfg.entry is None or destination not in cfg.nodes:return ()
        by_block={block.id:block for block in self.function.blocks}
        candidates=[]
        for block in self.function.blocks:
            for branch in (effect for effect in block.effects if isinstance(effect, BranchEffect)):
                pattern=arm_zero_flag_equal(block.effects, branch.condition) or arm_unsigned_hi(block.effects, branch.condition)
                if pattern is not None:candidates.append((block.id, branch, pattern))
        if not candidates:
            self.path_guard_cache[call.origin]=()
            self.path_guard_operands[call.origin]=()
            return ()
        edges=set(cfg.edges)
        for source, block in by_block.items():
            outgoing={edge for edge in edges if edge.source==source}
            if len(outgoing)<2 or any(isinstance(effect, BranchEffect) for effect in block.effects):continue
            jumps=[effect for effect in block.effects if isinstance(effect, JumpEffect)]
            if len(jumps)!=1:continue
            target=jumps[0].target
            if isinstance(target, BlockId):addresses={target.rva}
            else:
                try:values=self.demand.value(target)
                except DemandLimit:continue
                addresses={value-self.base for ref in values
                    if type(value:=self.demand.guard_concrete(ref)) is int}
            if len(addresses)==1:
                edges.difference_update(edge for edge in outgoing if edge.target.rva not in addresses)

        adjacency={node:[] for node in cfg.nodes}
        for edge in edges:adjacency.setdefault(edge.source, []).append(edge)

        def dominates(edge):
            seen={cfg.entry}
            todo=deque((cfg.entry,))
            while todo:
                current=todo.popleft()
                for candidate in adjacency.get(current, ()):
                    if candidate==edge or candidate.target in seen:continue
                    seen.add(candidate.target)
                    todo.append(candidate.target)
            return destination not in seen

        observations=[]
        for source, branch, pattern in candidates:
            for polarity, target in ((True, branch.if_true), (False, branch.if_false)):
                edge=next((edge for edge in adjacency.get(source, ()) if edge.target==target), None)
                if edge is None or not dominates(edge):continue
                try:values=self.demand.value(pattern.right)
                except DemandLimit:continue
                bounds={number for ref in values
                    if type(number:=self.demand.guard_concrete(ref)) is int}
                if len(bounds)!=1:continue
                observations.append((branch.origin, pattern.relation(polarity)+str(pattern.bits),
                    next(iter(bounds)), pattern.left))
        answer=tuple(sorted({row[:3] for row in observations}))
        self.path_guard_cache[call.origin]=answer
        self.path_guard_operands[call.origin]=tuple(observations)
        return answer

    def guarded_length_guards(self, call, recipes: tuple) -> tuple:
        """Relate a portable length recipe to exact SSE operands on this path.

        The result is a conditional guard annotation. It never replaces the
        residual recipe or makes an incomplete CFG a proof of safety.
        """
        key=call.origin, tuple(recipe.key for recipe in recipes)
        if key in self.guarded_length_cache:
            return self.guarded_length_cache[key]
        self.path_guards(call)
        observations=self.path_guard_operands.get(call.origin, ())
        equal=[row for row in observations if row[1]=='eq32' and row[2]==1]
        upper=[row for row in observations if row[1]=='ule32' and 0<=row[2]<0xffffffff]

        def symbolic_root(reference):
            for _ in range(12):
                node=self.port.engine.dag.nodes[reference]
                if node.op!=SymbolicOp.COPY:
                    return reference if node.op in (SymbolicOp.SYMBOL, SymbolicOp.MEMORY_READ) else None
                reference=node.operands[0]
            return None

        def exact_operand(reference):
            try:values=self.demand.value(reference)
            except DemandLimit:return None
            roots={symbolic_root(value) for value in values}
            if len(roots)!=1 or None in roots:
                return None
            root=next(iter(roots))
            return root if self.port.engine.dag.nodes[root].type.bits==32 else None

        answer=set()
        if equal and upper:
            for recipe in recipes:
                slots=unit_product_arguments(recipe.value)
                if slots is None:continue
                operands={slot:exact_operand(call.arguments[slot]) for slot in slots if slot<len(call.arguments)}
                if len(operands)!=2 or None in operands.values():continue
                for unit in equal:
                    unit_root=exact_operand(unit[3])
                    if unit_root is None:continue
                    for bound in upper:
                        bound_root=exact_operand(bound[3])
                        if bound_root is None:continue
                        if any(operands[first]==unit_root and operands[second]==bound_root
                               for first, second in (slots, slots[::-1])):
                            answer.add((call.origin, 'length-ule32', bound[2]))
        result=tuple(sorted(answer))
        self.guarded_length_cache[key]=result
        return result

    @staticmethod
    def constraints(*groups):
        values=[v for group in groups for v in group]
        numbers=[v for v in values if type(v) is int and v not in (0, 1)]
        return tuple(sorted({v for v in values if type(v) is int and v in (0, 1)}))+(() if not numbers else (min(numbers),))+tuple(sorted({v for v in values if type(v) is str}))

    def length_recipes(self, call, rule):
        key=call.origin, rule
        if key not in self.recipe_cache:self.recipe_cache[key]=self._length_recipes(call, rule)
        return self.recipe_cache[key]

    def _length_recipes(self, call, rule):
        if not rule.lengths or self.constants(call, rule.lengths):return ()
        values=(self.port.constant(1, ValueType.bv(self.port.engine.architecture.pointer_bits), call.origin),)
        for slot in rule.lengths:
            values=self.demand.union((self.port.operation(SymbolicOp.MUL, self.port.type_of(a), (a, b), call.origin),)
                for a in values for b in self.argument(call, slot))
        recipe=compile_recipe(self.demand, values, provenance=('Legacy source/copy length Cons use-def substitution',))
        if len(recipe.nodes)>256:
            self.unresolved_recipe_calls.add(call.origin)
            self.pending.append((call.origin, 'Length recipe exceeds 256 nodes; bound unknown, known source retained'))
            return ()
        return (ConstraintRecipe.wrap(recipe),)

    def bind_constraints(self, dependency, call):
        numbers=[]
        pending=[]
        unresolved_constraints=dependency.unresolved_constraints
        for recipe in dependency.recipes:
            self.port.validate_current()
            key=recipe.key, call.origin
            if key in self.bound_recipe_cache:
                concrete, residual, budgeted=self.bound_recipe_cache[key]
                numbers.extend(concrete)
                pending.extend(residual)
                unresolved_constraints |= budgeted
                continue
            try:values=recipe.value.instantiate(self.demand, call)
            except DemandLimit as error:
                self.local_failure(error, call.origin)
                values=(self.port.unknown(ValueType.bv(self.port.engine.architecture.pointer_bits), call.origin,
                    'Unresolved inherited length constraint: '+str(error)),)
            unresolved=[]
            concrete=[]
            residuals=[]
            budgeted=False
            for value in values:
                number=self.demand.guard_concrete(value)
                if type(number) is int:concrete.append(number)
                else:unresolved.append(value)
            if unresolved:
                residual=compile_recipe(self.demand, unresolved, provenance=recipe.value.provenance)
                if len(residual.nodes)>256:
                    budgeted=True
                    self.pending.append((call.origin, 'Residual length recipe budget; bound remains unknown and source propagation continues'))
                else:residuals.append(ConstraintRecipe.wrap(residual))
            self.bound_recipe_cache[key]=tuple(concrete), tuple(residuals), budgeted
            unresolved_constraints |= budgeted
            numbers.extend(concrete)
            pending.extend(residuals)
        return replace(dependency, constraints=self.constraints(dependency.constraints, numbers), recipes=tuple(dict.fromkeys(pending)),
            unresolved_constraints=unresolved_constraints)

    def register_source_fact(self, call:CallEffect, location:MemoryLocation, rule:ProcedureRule)->None:
        """Record the old callsite Source without demanding its later uses."""
        p=self.port
        e=p.engine
        site=self.base+call.site.point.instruction_rva
        if location.object_id is None:
            if call.origin not in self.unknown_roots:
                obj=MemoryObjectId.unknown(p.scope.function.binary, 'source-buffer', 'Unknown source destination', call.origin, p.scope.context)
                root=AccessRoot(obj, 'unknown', 'default', call.origin)
                e.add_object(MemoryObject(obj, 'Unresolved source destination'), root, ObjectCardinality.UNKNOWN, ObjectLifetime.UNKNOWN,
                             ('Actual source call has an unresolved destination; no NoAlias claim',))
                self.unknown_roots[call.origin]=root
            location=e.location(self.unknown_roots[call.origin], None, 8, e.architecture.endian, call.origin)
        key=call.origin, location.object_id, location.offset_lower
        lengths=self.constants(call, rule.lengths)
        if key not in self.source_bindings:
            value=p.symbol('taint-source-byte:'+call.origin, ValueType.bv(8), call.origin)
            gs=self.demand.value(call.guard)
            guard=gs[0] if len(gs)==1 else p.unknown(ValueType.boolean(), call.origin, 'Source guard alternatives')
            state=p.write(self.demand.initial.memory, location, value, guard, call.origin).state
            self.source_bindings[key]=self.regions.bind(state, location, site, call.origin, guard=guard, constraints=lengths,
                provenance=(rule.provenance, 'Actual CIR source call; buffer extent and feasibility remain may')+
                    tuple('Known-CIR path guard, CFG completeness unproved: '+repr(item) for item in self.path_guards(call)))

    def register_scalar_source_fact(self, call:CallEffect)->ScalarTaintFact|None:
        """Keep the old return Source on its actual CIR ValueRef, without an AST copy."""
        if not call.results:return None
        value_id=call.results[0].id
        if value_id not in self.scalar_source_facts:
            guards=self.demand.value(call.guard)
            guard=guards[0] if len(guards)==1 else None
            uncertain=guard is None or self.demand.guard_concrete(guard) is not True
            self.scalar_source_facts[value_id]=ScalarTaintFact(value_id,
                call.site.point, self.port.scope.context, guard,
                self.base+call.site.point.instruction_rva, call.origin, uncertain)
        return self.scalar_source_facts[value_id]

    def source(self, call, location, rule):
        site=self.base+call.site.point.instruction_rva
        if rule.operation=='source_return':self.register_scalar_source_fact(call)
        self.register_source_fact(call, location, rule)
        lengths=self.constants(call, rule.lengths)
        provisional=TaintDependency('source', site, lengths, (site,), True,
            handles=(('unknown', 'Source handle/length binding incomplete at '+call.origin),), unresolved_constraints=True)
        self.observe_sources((provisional,))
        handles=self.union_handles(self.handle(value) for value in self.argument(call, rule.source)) if rule.operation=='source_buffer' and rule.source is not None else ()
        recipes=self.length_recipes(call, rule)
        guards=tuple(sorted(set(self.path_guards(call)+self.guarded_length_guards(call, recipes))))
        dependency=TaintDependency('source', site, lengths, (site,), True, guards=guards, handles=handles, recipes=recipes,
            unresolved_constraints=call.origin in self.unresolved_recipe_calls)
        self.partial_sources.discard(provisional)
        self.query_sources.discard(provisional)
        self.observe_sources((dependency,))
        return dependency

    @staticmethod
    def union_handles(groups):return tuple(sorted(set(value for group in groups for value in group), key=repr))

    def handle(self, reference, seen=frozenset()):
        """Backward Udata handle lineage, including fdopen/socket override."""
        self.tick()
        d=self.demand
        e=self.port.engine
        if reference in seen:return (('unknown', 'recursive-handle'),)
        node=e.dag.nodes[reference]
        seen=seen|{reference}
        if node.op==SymbolicOp.SYMBOL:
            if node.value.startswith('argument:'):return (('argument', int(node.value.split(':')[1])),)
            call=d.return_calls.get(node.value)
            if call is not None:
                rule=lookup(d.call_name(call))
                site=self.base+call.site.point.instruction_rva
                if rule and rule.operation=='socket_handle':return (('socket', site),)
                if rule and rule.returns_file_handle:
                    inputs=(self.union_handles(self.handle(v, seen) for v in self.argument(call, rule.source))
                        if rule.operation=='file_handle' and rule.source is not None else ())
                    return self.union_handles(((('file', site),), inputs))
                values=[]
                for callee in self.call_functions(call):
                    summary=self.summaries.get(callee)
                    if summary:
                        for dep in summary.returns:
                            if dep.kind=='handle':values.append((dep.value,))
                            elif dep.kind=='argument':values.extend(self.handle(v, seen) for v in self.argument(call, dep.value))
                if values:return self.union_handles(values)
        if reference in d.loads:
            # Handle loads still require memory use/def correspondence. Unknown
            # cannot be relabeled as a file source simply because fread uses it.
            return (('unknown', d.loads[reference][3]),)
        if node.op in (SymbolicOp.ADD, SymbolicOp.SUB) and len(node.operands)==2:
            left, right=node.operands
            if node.op==SymbolicOp.ADD and e.dag.nodes[left].op==SymbolicOp.CONSTANT and e.dag.nodes[left].value==0:
                return self.handle(right, seen)
            if e.dag.nodes[right].op==SymbolicOp.CONSTANT and e.dag.nodes[right].value==0:
                return self.handle(left, seen)
        if node.operands:return self.union_handles(self.handle(v, seen) for v in node.operands)
        return (('unknown', node.origin),)

    def bind_handles(self, handles, call):
        return self.union_handles(self.union_handles(self.handle(v) for v in self.argument(call, value))
            if kind=='argument' else ((kind, value),) for kind, value in handles)

    def call_functions(self, call):
        if isinstance(call.target, DirectTarget):return (self.base+call.target.function.rva,)
        return tuple(self.targets.get(self.base+call.site.point.instruction_rva, ()))

    def import_source(self, dependency, call, location=None):
        """Project a detached callee may-source into this caller's memory scope."""
        p=self.port
        e=p.engine
        if location is None or location.object_id is None:
            key='summary-source:'+call.origin
            if key not in self.unknown_roots:
                obj=MemoryObjectId.unknown(p.scope.function.binary, 'summary-source', 'Unresolved callee source pointee', key, p.scope.context)
                root=AccessRoot(obj, 'unknown', 'default', call.origin)
                e.add_object(MemoryObject(obj, 'Callee source projection'), root, ObjectCardinality.UNKNOWN, ObjectLifetime.UNKNOWN,
                    ('Portable callee source; caller correspondence is may, not exact',))
                self.unknown_roots[key]=root
            location=e.location(self.unknown_roots[key], None, 8, e.architecture.endian, call.origin)
        if location.width_bits!=8:
            root=e.roots[location.object_id]
            upper=None if location.offset_upper is None else location.offset_upper+location.width_bits//8-1
            location=e.location(root, location.offset_lower, 8, e.architecture.endian, call.origin, upper=upper)
        key=call.origin, dependency.value, location.object_id, location.offset_lower, location.offset_upper
        if key in self.imported_bindings:return
        guards=self.demand.value(call.guard)
        guard=guards[0] if len(guards)==1 else p.unknown(ValueType.boolean(), call.origin, 'Callee call guard alternatives')
        value=p.symbol('summary-source-byte:'+str(dependency.value), ValueType.bv(8), call.origin)
        state=p.write(self.demand.initial.memory, location, value, guard, call.origin).state
        self.imported_bindings[key]=self.regions.bind(state, location, dependency.value, call.origin, guard=guard,
            constraints=dependency.constraints, provenance=('Actual callee summary projected at caller CIR call',
                'Inherited source guards: '+repr(dependency.guards), 'Representative source path: '+repr(dependency.path)))

    def bind_dependencies(self, dependencies, call, block, index, location=None, *, scalar=False):
        result=[]
        site=self.base+call.site.point.instruction_rva
        site_guards=self.path_guards(call)
        def inherit(value, formal):
            constraints=legacy_integer_constraints(value.constraints) if formal.constraint_type==4 else value.constraints
            return replace(value, constraints=self.constraints(constraints, formal.constraints),
                guards=tuple(sorted(set(value.guards+formal.guards+site_guards))),
                recipes=tuple(dict.fromkeys(value.recipes+formal.recipes)),
                constraint_type=formal.constraint_type or value.constraint_type,
                unresolved_constraints=value.unresolved_constraints or formal.unresolved_constraints)
        def bind_deferred(selector, formal):
            candidate=replace(selector.dependency,
                constraints=self.constraints(selector.dependency.constraints, formal.constraints),
                guards=tuple(sorted(set(selector.dependency.guards+formal.guards))),
                recipes=tuple(dict.fromkeys(selector.dependency.recipes+formal.recipes)),
                uncertain=selector.dependency.uncertain or formal.uncertain,
                unresolved_constraints=(selector.dependency.unresolved_constraints or
                    formal.unresolved_constraints),
                constraint_type=formal.constraint_type or selector.dependency.constraint_type)
            actuals=self.argument(call, selector.format_slot)
            indexes, unresolved=self.format_value_indexes(actuals, call.origin, diagnose=False)
            selected=[]
            if selector.position in indexes:
                selected.extend(self.bind_dependencies((candidate,), call, block, index, location, scalar=scalar))
            if not unresolved:return selected

            # The format is still a caller formal. Advance both sides of the
            # deferred relation without exposing the candidate as an ordinary
            # Source before a concrete format selects it. bind_dependencies
            # may update the current query frontier, so restore that book-
            # keeping after this deliberately latent binding.
            prior_query=set(self.query_sources)
            prior_partial=set(self.partial_sources)
            try:
                candidates=self.bind_dependencies((candidate,), call, block, index, location, scalar=True)
            finally:
                self.query_sources=prior_query
                self.partial_sources=prior_partial
            format_slots=set()
            for actual in actuals:
                for value in self.scalar_expression(actual, block, index, call.origin):
                    if value.kind in ('argument', 'scalar_argument') and type(value.value) is int:
                        format_slots.add(value.value)
            if not format_slots:
                selected.append(TaintDependency('unknown',
                    'Deferred vsnprintf format is not a caller formal at '+call.origin,
                    uncertain=True))
            else:
                selected.extend(TaintDependency('format_argument',
                    DeferredFormatArgument(slot, selector.position, candidate),
                    uncertain=True, unresolved_constraints=True)
                    for slot in sorted(format_slots) for candidate in candidates)
            return selected
        for dependency in sorted(source_antichain(dependencies, lambda narrow, broad:self.covered_sources.add((narrow, broad))),
                key=lambda dep:(dep.kind!='source', dependency_order(dep))):
            length_guards=self.guarded_length_guards(call, dependency.recipes)
            dependency=replace(dependency, guards=tuple(sorted(set(dependency.guards+length_guards))))
            provisional=None
            if dependency.kind=='source':
                # The callee's source-to-demand relation is already known.
                # Length/handle substitution can refine it, not make it absent.
                # Keep an explicitly unresolved may descriptor if that optional
                # refinement is interrupted; never retain foreign formal handles.
                provisional=replace(dependency, recipes=(), unresolved_constraints=True, uncertain=True,
                    guards=tuple(sorted(set(dependency.guards+site_guards))),
                    handles=tuple(('unknown', 'Interrupted caller handle binding at '+call.origin) if kind=='argument' else (kind, value)
                        for kind, value in dependency.handles),
                    path=dependency.path if site in dependency.path else dependency.path+(site,))
                self.observe_sources((provisional,))
            dependency=self.bind_constraints(dependency, call)
            if dependency.kind=='format_argument':
                result.extend(bind_deferred(dependency.value, dependency))
            elif dependency.kind=='hash':
                for root in self.table_state.bind_roots(dependency.value, call):result.extend(self.table_state.read(root, call))
            elif dependency.kind=='scalar_argument':
                for value in self.argument(call, dependency.value):
                    result.extend(inherit(dep, dependency) for dep in self.scalar_expression(value, block, index, call.origin))
            elif dependency.kind=='argument':
                for value in self.argument(call, dependency.value):
                    if dependency.offset:
                        delta=self.port.constant(dependency.offset%(1<<self.port.engine.architecture.pointer_bits), self.port.type_of(value), call.origin)
                        value=self.port.operation(SymbolicOp.ADD, self.port.type_of(value), (value, delta), call.origin)
                    result.extend(inherit(dep, dependency)
                        for dep in self.buffer(block, index, value, call.origin, whole_region=dependency.offset is None,
                            width_bits=dependency.access_width, byte_access=dependency.byte_access))
            elif dependency.kind=='global':
                value=self.port.constant(dependency.value, ValueType.bv(self.port.engine.architecture.pointer_bits), call.origin)
                result.extend(inherit(dep, dependency) for dep in self.buffer(block, index, value, call.origin))
            else:
                bound=replace(dependency, guards=tuple(sorted(set(dependency.guards+site_guards))),
                    handles=self.bind_handles(dependency.handles, call))
                if bound.kind=='source':
                    if self.active_sink is not None:self.partial_sources.add(bound)
                    if not scalar:self.import_source(bound, call, location)
                result.append(bound)
            if provisional is not None:
                self.partial_sources.discard(provisional)
                self.query_sources.discard(provisional)
                self.observe_sources((bound,))
        # Repeated callsites are summarized, not expanded into infinite paths.
        # The uncertainty marker makes this unsuitable as a concrete witness.
        return self.union((tuple(replace(d, path=d.path if site in d.path else d.path+(site,), uncertain=True,
                     guards=tuple(sorted(set(d.guards+site_guards))))
                     for d in result),))

    def expression(self, reference, block, index, origin):
        key=reference, block, index
        if key in self.expression_cache:return self.expression_cache[key]
        if key in self.expression_active:return (TaintDependency('unknown', 'Recursive value requirement', uncertain=True),)
        if len(self.expression_active)>=120:
            return (self.local_failure(DemandLimit('Taint expression demand depth budget', dimension='depth'), origin),)
        self.expression_active.add(key)
        try:
            result=self._expression(reference, block, index, origin)
            self.expression_cache[key]=result
            return result
        finally:self.expression_active.remove(key)

    def scalar_expression(self, reference, block, index, origin):
        """Value taint, keeping formal scalar inputs apart from pointees."""
        self.tick()
        key=reference, block, index
        if key in self.scalar_cache:return self.scalar_cache[key]
        if key in self.scalar_active or len(self.scalar_active)>=120:
            return (TaintDependency('unknown', 'Unresolved scalar value recursion', uncertain=True),)
        self.scalar_active.add(key)
        d=self.demand
        node=self.port.engine.dag.nodes[reference]
        try:
            if node.op==SymbolicOp.SYMBOL and node.value.startswith('argument:'):
                result=(TaintDependency('scalar_argument', int(node.value.split(':')[1])),)
            elif node.op==SymbolicOp.SYMBOL and node.value in d.return_calls:
                call=d.return_calls[node.value]
                source_block, source_index, _=self.calls[call.origin]
                if all(d.guard_concrete(value) is False for value in d.value(call.guard)):
                    result=(TaintDependency('unknown', 'Nonexecuted call has no defined scalar result', uncertain=True),)
                elif lookup(d.call_name(call)) is not None:result=self.expression(reference, block, index, origin)
                else:
                    groups=[]
                    callees=self.call_functions(call)
                    for callee in callees:
                        summary=self.summaries.get(callee)
                        if summary is None or summary.scalar_returns is None:
                            groups.append((TaintDependency('unknown', 'Callee scalar return mode unavailable: '+hex(callee), uncertain=True),))
                        else:
                            groups.append(self.bind_dependencies(summary.scalar_returns, call, source_block, source_index, scalar=True))
                            if summary.pending:groups.append((TaintDependency('unknown', 'Incomplete callee scalar return', uncertain=True),))
                    if not callees:groups.append((TaintDependency('unknown', 'Unresolved scalar return target', uncertain=True),))
                    result=self.union(groups)
            elif reference in d.loads:result=self.expression(reference, block, index, origin)
            elif node.op in (SymbolicOp.UNKNOWN, SymbolicOp.SYMBOL, SymbolicOp.MEMORY_READ):
                result=(TaintDependency('unknown', 'Unresolved scalar value: '+str(node.value or node.origin), uncertain=True),)
            else:result=self.union(self.scalar_expression(child, block, index, origin) for child in node.operands) if node.operands else ()
            self.scalar_cache[key]=result
            return result
        finally:self.scalar_active.remove(key)

    def length_taint(self, call, rule, block, index):
        return self.union(self.scalar_expression(value, block, index, call.origin)
            for slot in rule.lengths for value in self.argument(call, slot))

    def in_length_channel(self, operation):
        """Length-only Sources must never become buffer Sources on a limit."""
        saved=self.partial_sources, self.query_sources
        self.partial_sources=set()
        self.query_sources=set()
        try:return operation()
        except (DemandLimit, BudgetExceeded, RecursionError):
            if self.active_sink is not None:
                unknown=TaintDependency('unknown', 'Length-taint query incomplete', uncertain=True)
                self.active_sink=replace(self.active_sink, length_dependencies=tuple(sorted(self.partial_sources|self.query_sources, key=dependency_order))+(unknown,))
            raise
        finally:self.partial_sources, self.query_sources=saved

    def destination(self, reference, origin):
        """Stable formal destination use/def, separate from source taint."""
        p=self.port
        e=p.engine
        binding=self.demand.address_binding(reference)
        if binding:
            root, offset=binding
            if root.region=='stack' and offset is not None:
                bits=e.architecture.pointer_bits
                signed=(offset+(1<<(bits-1)))%(1<<bits)-(1<<(bits-1))
                return (-signed,), ()
            for slot, argument in getattr(e, 'argument_roots', {}).items():
                if root.object_id==argument.object_id:return (), (BufferDestination('argument', slot, offset),)
        absolute=p.concrete(reference)
        if type(absolute) is int and e.address(absolute):return (), (BufferDestination('global', absolute),)
        # LegacyDemand's old DDG recurrence is base + stride*i. The old
        # forward pass also observes the first loop transfer; retain that
        # concrete MAY alongside the unbounded symbolic remainder. Only a
        # single, fully affine loop symbol with a resolved stack base qualifies.
        todo=[reference]
        seen=set()
        indices=set()
        while todo and len(seen)<128:
            item=todo.pop()
            if item in seen:continue
            seen.add(item)
            node=e.dag.nodes[item]
            if node.op==SymbolicOp.SYMBOL and node.value=='i':indices.add(item)
            else:todo.extend(node.operands)
        if not todo and len(indices)==1:
            affine=self.demand.affine(reference, next(iter(indices)))
            if affine is not None and affine[0]:
                bits=e.architecture.pointer_bits
                first=(affine[1]+affine[0])%(1<<bits)
                first_binding=self.demand.address_binding(p.constant(first, p.type_of(reference), origin))
                if first_binding and first_binding[0].region=='stack':
                    signed=(first_binding[1]+(1<<(bits-1)))%(1<<bits)-(1<<(bits-1))
                    return (-signed,), (BufferDestination('unknown', 'Unbounded loop destination '+origin, None),)
        return (), (BufferDestination('unknown', origin, None),)

    def bind_sink(self, sink, call, block, index):
        offsets=set(sink.offsets)
        destinations=[]
        p=self.port
        for destination in sink.destinations:
            if destination.kind!='argument':
                destinations.append(destination)
                continue
            if destination.offset is None:
                destinations.append(BufferDestination('unknown', 'Unknown destination displacement at '+call.origin, None))
                continue
            for value in self.argument(call, destination.value):
                if destination.offset:
                    delta=p.constant(destination.offset%(1<<p.engine.architecture.pointer_bits), p.type_of(value), call.origin)
                    value=p.operation(SymbolicOp.ADD, p.type_of(value), (value, delta), call.origin)
                sizes, pending=self.destination(value, call.origin)
                offsets.update(sizes)
                destinations.extend(pending)
        bound=replace(sink, offsets=tuple(sorted(offsets)), destinations=tuple(sorted(set(destinations), key=repr)))
        if sink.length_dependencies:bound=replace(bound, length_dependencies=(TaintDependency('unknown', 'Caller length-taint binding pending', uncertain=True),))
        self.active_sink=bound
        try:
            buffers=self.bind_dependencies(sink.dependencies, call, block, index)
        except DemandLimit as error:
            if error.dimension not in ('alternatives', 'depth'):raise
            self.pending.append((call.origin, 'Inherited buffer binding incomplete: '+str(error)))
            buffers=(tuple(sorted(self.partial_sources|self.query_sources, key=dependency_order))+
                (TaintDependency('unknown', 'Inherited buffer alternatives incomplete', uncertain=True),))
        self.active_sink=replace(bound, dependencies=buffers)
        if sink.length_dependencies:
            try:lengths=self.in_length_channel(lambda:self.bind_dependencies(sink.length_dependencies, call, block, index, scalar=True))
            except DemandLimit as error:
                if error.dimension not in ('alternatives', 'depth'):raise
                self.pending.append((call.origin, 'Inherited length binding incomplete: '+str(error)))
                lengths=self.active_sink.length_dependencies
            self.active_sink=replace(self.active_sink, length_dependencies=lengths)
        return self.active_sink

    def _expression(self, reference, block, index, origin):
        self.tick()
        p=self.port
        d=self.demand
        e=p.engine
        node=e.dag.nodes[reference]
        if node.op==SymbolicOp.SYMBOL:
            if node.value.startswith('argument:'):return (TaintDependency('argument', int(node.value.split(':')[1])),)
            if node.value in d.return_calls:
                call=d.return_calls[node.value]
                source_block, source_index, _=self.calls[call.origin]
                rule=lookup(d.call_name(call))
                if rule and rule.operation=='source_return':return (self.source(call, e.location(None, None, 8, e.architecture.endian, call.origin), rule),)
                if rule and rule.operation=='deref_return':
                    return self.union(self.buffer(source_block, source_index, pointer, call.origin)
                        for address in self.argument(call, rule.source)
                        for pointer in d.read(source_block, source_index, address, ArgumentRead(e.architecture.pointer_bits, e.architecture.endian, call.origin), 0))
                if rule and rule.operation in ('file_handle', 'socket_handle'):
                    return tuple(TaintDependency('handle', handle) for handle in self.handle(reference))
                if rule and rule.operation in ('return_alias', 'stateful_token', 'integer_return'):
                    if rule.operation=='stateful_token':return self.token_dependencies(call, source_block, source_index)
                    dependencies=self.union(self.buffer(source_block, source_index, v, call.origin) for v in self.argument(call, rule.source))
                    return tuple(replace(dep, constraints=legacy_integer_constraints(dep.constraints) if rule.constraint_type==4 else dep.constraints,
                        constraint_type=rule.constraint_type) for dep in dependencies) if rule.operation=='integer_return' else dependencies
                callees=self.call_functions(call)
                result=self.union(self.bind_dependencies(self.summaries[f].returns, call, source_block, source_index)
                    for f in callees if f in self.summaries)
                return result or (TaintDependency('unknown', 'Unresolved callee return taint at '+call.origin, uncertain=True),)
        if reference in d.loads:
            return self.buffer(*self.load_positions.get(d.loads[reference][3], (block, index)), d.loads[reference][0], origin,
                width_bits=d.loads[reference][1], byte_access=True)
        if node.op in (SymbolicOp.UNKNOWN, SymbolicOp.SYMBOL, SymbolicOp.MEMORY_READ):
            return (TaintDependency('unknown', 'Unresolved value taint: '+str(node.value or node.origin), uncertain=True),)
        return self.union(self.expression(child, block, index, origin) for child in node.operands) if node.operands else ()

    def token_dependencies(self, call, block, index):
        """Session-local backward use/def for old strtok's r1001 SAVE_PTR."""
        p=self.port
        d=self.demand
        arguments=self.argument(call, 0)
        choices={d.guard_concrete(v) for v in arguments}
        groups=[]
        if choices!={0}:
            groups.extend(self.buffer(block, index, value, call.origin) for value in arguments if d.guard_concrete(value)!=0)
        if 0 not in choices and None not in choices:return self.union(groups)
        if None in choices:groups.append((TaintDependency('unknown', 'strtok new/saved pointer choice unresolved', uncertain=True),))
        todo=deque(((block, index),))
        seen=set()
        while todo:
            current, cutoff=todo.popleft()
            self.tick()
            if (current, cutoff) in seen:
                groups.append((TaintDependency('unknown', 'strtok saved pointer loop frontier', uncertain=True),))
                continue
            seen.add((current, cutoff))
            defined=False
            for position in range(cutoff-1, -1, -1):
                previous=d.blocks[current].effects[position]
                if not isinstance(previous, CallEffect):continue
                rule=lookup(d.call_name(previous))
                if rule is None:
                    groups.append((TaintDependency('unknown', 'Unmodeled call may change strtok saved pointer', uncertain=True),))
                    continue
                if rule.operation!='stateful_token':continue
                guards={d.guard_concrete(g) for g in d.value(previous.guard)}
                if guards=={False}:continue
                values=self.argument(previous, 0)
                prior={d.guard_concrete(v) for v in values}
                if prior=={0}:continue
                groups.extend(self.buffer(current, position, value, previous.origin) for value in values if d.guard_concrete(value)!=0)
                if None not in prior and 0 not in prior and guards=={True}:
                    defined=True
                    break
                groups.append((TaintDependency('unknown', 'strtok saved pointer conditional definition', uncertain=True),))
            if not defined:
                if current==self.function.entry or not d.predecessors[current]:
                    groups.append((TaintDependency('unknown', 'strtok saved pointer uninitialized in this context', uncertain=True),))
                todo.extend((pre, len(d.blocks[pre].effects)) for pre in d.predecessors[current])
        return self.union(groups)

    def edge_policy(self, predecessor, successor, location):
        """Recognize the original procedure-result guard on an exact pointer.

        Unrecognized guards and MayAlias never justify a kill. The descriptor
        records a legacy heuristic, not a proof that the path is feasible.
        """
        key=predecessor, successor, location.object_id, location.offset_lower
        if key in self.edge_policy_cache:return self.edge_policy_cache[key]
        p=self.port
        e=p.engine
        d=self.demand
        result=[]
        possible=True
        for effect in d.blocks[predecessor].effects:
            if not isinstance(effect, BranchEffect) or successor not in (effect.if_true, effect.if_false):continue
            polarity=successor==effect.if_true
            try:values=d.value(effect.condition)
            except DemandLimit as error:
                self.local_failure(error, effect.origin)
                continue
            if values and all(d.guard_concrete(v) is (not polarity) for v in values):
                possible=False
                break
            if len(values)!=1:continue
            ref=values[0]
            node=e.dag.nodes[ref]
            while node.op in (SymbolicOp.COPY, SymbolicOp.NOT):
                if node.op==SymbolicOp.NOT:polarity=not polarity
                ref=node.operands[0]
                node=e.dag.nodes[ref]
            if node.op not in (SymbolicOp.EQ, SymbolicOp.ULT, SymbolicOp.SLT):continue
            left, right=node.operands
            bound=d.guard_concrete(right)
            relation='eq' if node.op==SymbolicOp.EQ else 'lt'
            if type(bound) is not int:
                bound=d.guard_concrete(left)
                left=right
                relation='eq' if node.op==SymbolicOp.EQ else 'gt'
            if type(bound) is not int:continue
            if not polarity:relation={'eq':'ne', 'lt':'ge', 'gt':'le'}[relation]
            value=e.dag.nodes[left]
            while value.op in (SymbolicOp.COPY, SymbolicOp.ZERO_EXTEND, SymbolicOp.SIGN_EXTEND):
                left=value.operands[0]
                value=e.dag.nodes[left]
            if value.op!=SymbolicOp.SYMBOL or value.value not in d.return_calls:continue
            call=d.return_calls[value.value]
            rule=lookup(d.call_name(call))
            if not rule or not rule.constraint_type:continue
            slots=(0, 1) if rule.name in ('strcmp', 'strcasecmp', 'stricmp') else (rule.source,)
            for slot in slots:
                if slot is None:continue
                for address in self.argument(call, slot):
                    source=self.location(address, call.origin)
                    if p.alias(d.initial.memory, source, location).kind!=AliasKind.MUST:continue
                    decision=legacy_constraint(rule.constraint_type, relation, bound)
                    result.append((decision, effect.origin, relation, bound))
        answer=possible, tuple(result)
        self.edge_policy_cache[key]=answer
        return answer

    def buffer(self, block, index, reference, origin, *, whole_region=False, width_bits=8, byte_access=False, export_root=None):
        self.tick()
        p=self.port
        e=p.engine
        d=self.demand
        node=e.dag.nodes[reference]
        if not byte_access and node.op==SymbolicOp.SYMBOL and node.value in d.return_calls:
            rule=lookup(d.call_name(d.return_calls[node.value]))
            if rule and rule.operation in ('source_return', 'return_alias', 'integer_return', 'stateful_token', 'deref_return'):
                # Apply the actual old return-taint rule before searching
                # unrelated memory through an opaque return-address symbol.
                return self.expression(reference, block, index, origin)
        location=self.location(reference, origin)
        if width_bits!=8:
            root=e.roots[location.object_id] if location.object_id is not None else None
            location=e.location(root, location.offset_lower, width_bits, e.architecture.endian, origin, upper=location.offset_upper)
        if whole_region and location.object_id is not None:
            location=e.location(e.roots[location.object_id], None, 8, e.architecture.endian, origin)
        key=(block, index, location.object_id, location.offset_lower, location.offset_upper, width_bits, byte_access, reference if location.object_id is None else None, export_root)
        if key in self.memo:return self.memo[key]
        if key in self.active:return (TaintDependency('unknown', 'Recursive memory requirement', uncertain=True),)
        self.active.add(key)
        result=[]
        visited=set()
        todo=deque(((block, index, (), ()),))
        try:
            while todo:
                current, cutoff, bounds, guards=todo.popleft()
                self.tick()
                if (current, cutoff, bounds, guards) in visited:continue
                visited.add((current, cutoff, bounds, guards))
                killed=False
                start=len(result)
                for position in range(cutoff-1, -1, -1):
                    effect=d.blocks[current].effects[position]
                    if isinstance(effect, StoreEffect):
                        if getattr(effect.guard, 'value', None) is False:continue
                        # Same selection order as P6/old store alias rules:
                        # compare address correspondence before demanding value
                        # slices from unrelated definitions.
                        binding=d.local_address(effect.address)
                        for binding in (binding,):
                            written=e.location(*binding, effect.width_bits, effect.endian, effect.origin) if binding else e.location(None, None, effect.width_bits, effect.endian, effect.origin)
                            alias=p.alias(d.initial.memory, written, location)
                            if alias.kind==AliasKind.NO:continue
                            corresponding=(written.object_id is not None and written.object_id==location.object_id)
                            if not corresponding:
                                result.append(TaintDependency('unknown', 'Unproved store correspondence at '+effect.origin, uncertain=True))
                                continue
                            try:values=d.value(effect.value)
                            except DemandLimit as error:
                                result.append(self.local_failure(error, effect.origin))
                                continue
                            for value in values:result.extend(self.expression(value, current, position, effect.origin))
                            # Follow actual definition ordering through the port.
                            for value in values:p.write(d.initial.memory, written, value, d.value(effect.guard)[0], effect.origin)
                            a, b=written.byte_interval, location.byte_interval
                            covered=(written.object_id==location.object_id and written.object_id is not None and a is not None and b is not None
                                and a[0]<=b[0] and b[1]<=a[1] and e.object_facts[written.object_id].cardinality==ObjectCardinality.SINGLETON)
                            if byte_access and covered and getattr(effect.guard, 'value', None) is True:killed=True
                    elif isinstance(effect, CallEffect):
                        if all(d.guard_concrete(g) is False for g in d.value(effect.guard)):continue
                        rule=lookup(d.call_name(effect))
                        site=self.base+effect.site.point.instruction_rva
                        if rule and rule.operation in ('source_buffer', 'copy', 'format_output', 'format_output_va_list', 'format_input'):
                            destinations=(rule.destination,) if rule.destination is not None else self.format_arguments(effect, rule)
                            for slot in destinations:
                                for target in self.argument(effect, slot):
                                    dest=self.procedure_region(effect, rule, target)
                                    if dest is None:continue
                                    alias=p.alias(d.initial.memory, dest, location)
                                    if alias.kind==AliasKind.NO:continue
                                    if export_root is not None and dest.object_id!=export_root:
                                        result.append(TaintDependency('unknown', 'Possible alias is not an argument-base definition at '+effect.origin, uncertain=True))
                                        continue
                                    if rule.operation=='source_buffer':result.append(self.source(effect, dest, rule))
                                    elif rule.operation=='format_output_va_list':
                                        copied=self.va_list_dependencies(effect, current, position, rule)
                                        lengths=self.constants(effect, rule.lengths)
                                        if rule.lengths and not lengths:lengths=('S',)
                                        self.observe_sources(copied)
                                        result.extend(replace(dep, constraints=self.constraints(dep.constraints, lengths),
                                            uncertain=dep.uncertain or alias.kind!=AliasKind.MUST,
                                            recipes=tuple(dict.fromkeys(dep.recipes+self.length_recipes(effect, rule))),
                                            unresolved_constraints=dep.unresolved_constraints or effect.origin in self.unresolved_recipe_calls)
                                            for dep in copied)
                                    else:
                                        sources=(rule.source,) if rule.source is not None else self.format_arguments(effect, rule)
                                        lengths=self.constants(effect, rule.lengths)
                                        for src in sources:
                                            for value in self.argument(effect, src):
                                                copied=self.buffer(current, position, value, effect.origin)
                                                self.observe_sources(copied)
                                                unresolved_length=effect.origin in self.unresolved_recipe_calls
                                                if rule.operation=='copy' and rule.lengths:
                                                    if effect.origin in self.transfer_length_failures:
                                                        unresolved_length=True
                                                    else:
                                                        try:
                                                            length_dependencies=self.in_length_channel(
                                                                lambda:self.length_taint(effect, rule, current, position))
                                                            lengths=self.constraints(lengths,
                                                                uniform_copy_length_constraints(length_dependencies))
                                                        except DemandLimit as error:
                                                            if error.dimension not in ('alternatives', 'depth'):raise
                                                            # Length is an optional refinement of a
                                                            # data Source already found through this
                                                            # copy.  Losing the refinement must not
                                                            # erase the data-flow fact. Cache the
                                                            # failed refinement at this immutable
                                                            # callsite so repeated paths do not spend
                                                            # the entire taint worklist on it.
                                                            self.transfer_length_failures.add(effect.origin)
                                                            self.pending.append((effect.origin,
                                                                'Copy transfer length binding incomplete: '+str(error)))
                                                            unresolved_length=True
                                                    if unresolved_length:
                                                        result.append(TaintDependency('unknown',
                                                            'Copy transfer length alternatives incomplete at '+effect.origin,
                                                            uncertain=True))
                                                result.extend(replace(dep, constraints=self.constraints(dep.constraints, lengths), uncertain=dep.uncertain or alias.kind!=AliasKind.MUST,
                                                    recipes=tuple(dict.fromkeys(dep.recipes+self.length_recipes(effect, rule))),
                                                    unresolved_constraints=dep.unresolved_constraints or unresolved_length)
                                                    for dep in copied)
                        for callee in self.call_functions(effect):
                            summary=self.summaries.get(callee)
                            if summary is None:continue
                            if summary.pending:result.append(TaintDependency('unknown', 'Incomplete callee memory summary: '+hex(callee), uncertain=True))
                            for slot, dependencies in summary.outputs:
                                for address in self.argument(effect, slot):
                                    target=self.location(address, effect.origin)
                                    if target.object_id is not None:target=e.location(e.roots[target.object_id], None, 8, e.architecture.endian, effect.origin)
                                    alias=p.alias(d.initial.memory, target, location)
                                    if alias.kind!=AliasKind.NO:
                                        if export_root is not None and target.object_id!=export_root:
                                            result.append(TaintDependency('unknown', 'Unproved callee argument-definition correspondence at '+effect.origin, uncertain=True))
                                        else:result.extend(self.bind_dependencies(dependencies, effect, current, position, location))
                            if summary.global_outputs is None:
                                result.append(TaintDependency('unknown', 'Callee global export mode unavailable: '+hex(callee), uncertain=True))
                            for output in summary.global_outputs or ():
                                target=global_output_location(self, output, effect.origin)
                                if p.alias(d.initial.memory, target, location).kind==AliasKind.NO:continue
                                if export_root is not None and target.object_id!=export_root:
                                    result.append(TaintDependency('unknown', 'Global definition may alias argument; destination correspondence unresolved', uncertain=True))
                                else:result.extend(self.bind_dependencies(output.dependencies, effect, current, position, location))
                        if rule is None and (not self.call_functions(effect) or any(f not in self.summaries for f in self.call_functions(effect))):
                            result.append(TaintDependency('unknown', 'Unmodeled call memory effect at '+str(site), uncertain=True))
                        if rule and rule.operation=='declared_unmodeled_source':
                            result.append(TaintDependency('unknown', 'Declared source has no original procedure model: '+rule.name, uncertain=True))
                        if rule and rule.operation=='hash_search' and self.constants(effect, (2,))!=(1,) and self.table_state.data_field_query(reference, effect):
                            for pointer in self.argument(effect, 4):
                                result.extend(self.table_state.read(self.table_state.root(pointer, effect.origin), effect))
                    elif isinstance(effect, UnknownEffect) and effect.may_write_regions:
                        result.append(TaintDependency('unknown', 'Unsupported memory effect: '+effect.source_opcode, uncertain=True))
                    if killed:break
                if not killed:
                    if current==self.function.entry or not d.predecessors[current]:
                        argument=next((slot for slot, root in getattr(e, 'argument_roots', {}).items() if root.object_id==location.object_id), None)
                        if argument is not None:result.append(TaintDependency('argument', argument, offset=None if whole_region else location.offset_lower,
                            uncertain=whole_region, access_width=width_bits, byte_access=byte_access))
                        else:result.extend(self.expression(reference, block, index, origin))
                        absolute=p.concrete(reference)
                        if type(absolute) is int and e.address(absolute):
                            permissions=next((flags for start, data, size, flags in getattr(e, 'segments', ()) if start<=absolute<start+size), None)
                            # A file-backed immutable literal is not a caller-
                            # mutable global requirement. Keep actual local
                            # writes/unknown effects above; this only controls
                            # the initial-state dependency exported to callers.
                            if permissions is None or permissions&2:result.append(TaintDependency('global', absolute, uncertain=True))
                    for pre in d.predecessors[current]:
                        possible, policies=self.edge_policy(pre, current, location)
                        if not possible or any(decision.kill for decision, _, _, _ in policies):continue
                        extra=tuple(value for decision, _, _, _ in policies for value in decision.constraints)
                        evidence=tuple((source, relation, bound) for _, source, relation, bound in policies)
                        todo.append((pre, len(d.blocks[pre].effects), self.constraints(bounds, extra), tuple(sorted(set(guards+evidence)))))
                result[start:]=[replace(dep, constraints=self.constraints(dep.constraints, bounds), guards=tuple(sorted(set(dep.guards+guards)))) for dep in result[start:]]
            answer=self.union((result,))
            self.memo[key]=answer
            return answer
        finally:self.active.remove(key)

    def format_arguments(self, call, rule):
        key=call.origin, rule
        if key not in self.format_cache:self.format_cache[key]=self._format_arguments(call, rule)
        return self.format_cache[key]

    def _format_arguments(self, call, rule):
        indexes, _=self.format_string_indexes(call, rule)
        return tuple(rule.variadic_start+i for i in indexes) if rule.variadic_start is not None else ()

    def format_string_indexes(self, call, rule):
        """Return old FormatParser string positions and an unresolved flag."""
        key=call.origin, rule
        if key not in self.format_descriptor_cache:
            self.format_descriptor_cache[key]=self._format_string_indexes(call, rule)
        return self.format_descriptor_cache[key]

    def _format_string_indexes(self, call, rule):
        if rule.format_index is None:return (), False
        return self.format_value_indexes(self.argument(call, rule.format_index), call.origin)

    def format_value_indexes(self, addresses, origin, *, diagnose=True):
        """Parse concrete format values without assuming an external call ABI."""
        p=self.port
        e=p.engine
        strings=[]
        unresolved=False
        for address in addresses:
            base=p.concrete(address)
            if type(base) is not int:
                unresolved=True
                continue
            data=[]
            terminated=False
            for i in range(4096):
                binding=e.address(base+i)
                if binding is None:break
                loc=e.location(*binding, 8, e.architecture.endian, origin)
                read=p.read(self.demand.initial.memory, loc, p.constant(True, ValueType.boolean(), origin), origin).value
                value=p.guard_concrete(read)
                if value is None:
                    # Retain the original FormatParser loader interpretation
                    # as one possible format, together with an explicit unknown
                    # remainder. It cannot prove a runtime bound or clean flow.
                    unresolved=True
                    value=p.concrete(read)
                if value is None:break
                if value==0:
                    terminated=True
                    break
                data.append(value)
            if terminated:strings.append(bytes(data))
            else:unresolved=True
        if diagnose and (unresolved or not strings):
            note='Unknown format at '+origin+'; variadic coverage incomplete'
            if note not in self.diagnostics:self.diagnostics.append(note)
        indexes=tuple(sorted({i for data in strings for i, kind in enumerate(legacy_format_parameters(data)) if kind=='s'}))
        return indexes, unresolved or not strings

    def va_list_dependencies(self, call, block, index, rule):
        """Apply old vsnprintf Store/va_list matching through versioned reads.

        The legacy helper selects a tainted ``Store`` only when its address is
        the va_list base or base plus a constant, then indexes the parsed
        format with ``offset % arch.bytes``.  Preserve that unusual rule
        exactly; unresolved address correspondence remains an explicit may.
        """
        p=self.port
        e=p.engine
        d=self.demand
        groups=[]
        trace={'origin':call.origin, 'format_indexes':(), 'format_unresolved':False,
            'format_slots':(), 'bases':[], 'stores':[], 'reads':[]}
        string_indexes, format_unresolved=self.format_string_indexes(call, rule)
        trace['format_indexes']=string_indexes
        trace['format_unresolved']=format_unresolved
        if format_unresolved:
            groups.append((TaintDependency('unknown', 'vsnprintf format/va_list correspondence unresolved', uncertain=True),))
        format_slots=set()
        if format_unresolved:
            for value in self.argument(call, rule.format_index):
                for dependency in self.scalar_expression(value, block, index, call.origin):
                    if dependency.kind in ('argument', 'scalar_argument') and type(dependency.value) is int:
                        format_slots.add(dependency.value)
        trace['format_slots']=tuple(sorted(format_slots))
        if not string_indexes and not format_slots:
            self.va_list_diagnostics.append(trace)
            return self.union(groups)
        word=e.architecture.pointer_bits//8
        mask=(1<<e.architecture.pointer_bits)-1
        read=ArgumentRead(e.architecture.pointer_bits, e.architecture.endian, call.origin)
        for va_list in self.argument(call, rule.source):
            base=d.address_binding(va_list)
            trace['bases'].append(str(base))
            if base is None or base[1] is None:
                groups.append((TaintDependency('unknown', 'vsnprintf va_list base unresolved at '+call.origin, uncertain=True),))
                continue
            todo=deque(((block, index),))
            seen=set()
            addresses={}
            unresolved=False
            while todo:
                current, cutoff=todo.popleft()
                if (current, cutoff) in seen:continue
                seen.add((current, cutoff))
                for effect in reversed(d.blocks[current].effects[:cutoff]):
                    if not isinstance(effect, StoreEffect) or getattr(effect.guard, 'value', None) is False:continue
                    binding=d.local_address(effect.address)
                    if binding is None or binding[1] is None:
                        # Entry va_list saves are commonly addressed through a
                        # copied frame register.  The generic local classifier
                        # deliberately keeps that offset open; use the already
                        # validated exact-entry-SP proof before applying the
                        # old base/base+constant Store selector.
                        exact=d.exact_stack_address(effect.address)
                        if exact is not None:binding=exact
                    if len(trace['stores'])<64:
                        trace['stores'].append({'origin':effect.origin, 'binding':str(binding),
                            'same_object':bool(binding and binding[0].object_id==base[0].object_id)})
                    if binding is None:
                        unresolved=True
                        continue
                    if binding[0].object_id!=base[0].object_id:continue
                    if binding[1] is None:
                        unresolved=True
                        continue
                    offset=(binding[1]-base[1])&mask
                    position=offset%word
                    if position not in string_indexes and not format_slots:continue
                    addresses[(binding[0].object_id, binding[1])]=(effect.address, position)
                todo.extend((pre, len(d.blocks[pre].effects)) for pre in d.predecessors[current])
            for operand, position in addresses.values():
                for address in d.value(operand):
                    try:pointers=d.read(block, index, address, read, 0)
                    except DemandLimit as error:
                        groups.append((self.local_failure(error, call.origin),))
                        continue
                    for pointer in pointers:
                        if d.guard_concrete(pointer)==0:continue
                        dependencies=self.buffer(block, index, pointer, call.origin)
                        if len(trace['reads'])<64:
                            trace['reads'].append({'store':d.loads.get(pointer, ('',))[0] if pointer in d.loads else None,
                                'position':position, 'dependency_kinds':tuple(dep.kind for dep in dependencies)})
                        if position in string_indexes:groups.append(dependencies)
                        if format_unresolved:
                            for slot in sorted(format_slots):
                                groups.append(tuple(TaintDependency('format_argument',
                                    DeferredFormatArgument(slot, position, dependency),
                                    uncertain=True, unresolved_constraints=True)
                                    for dependency in dependencies))
            if unresolved:
                groups.append((TaintDependency('unknown', 'vsnprintf Store/va_list alias unresolved at '+call.origin, uncertain=True),))
        self.va_list_diagnostics.append(trace)
        return self.union(groups)

    def argv_dependencies(self, call, block, index):
        """Old argv Store-slot / zero-terminator rule, with versioned reads."""
        p=self.port
        e=p.engine
        d=self.demand
        word=e.architecture.pointer_bits//8
        groups=[]
        contexts=[(block, index)]+[(pre, len(d.blocks[pre].effects)) for pre in d.predecessors[block]]
        for argv in self.argument(call, 1):
            base=d.address_binding(argv)
            ends=set()
            if base and base[1] is not None:
                for current, cutoff in contexts:
                    for effect in reversed(d.blocks[current].effects[:cutoff]):
                        if not isinstance(effect, StoreEffect) or effect.width_bits!=word*8 or getattr(effect.guard, 'value', None) is not True:continue
                        if not all(d.guard_concrete(value)==0 for value in d.value(effect.value)):continue
                        target=d.local_address(effect.address)
                        if not target or target[0]!=base[0] or target[1] is None:continue
                        offset=(target[1]-base[1])%(1<<e.architecture.pointer_bits)
                        if offset%word==0 and 0<offset//word<=256:
                            ends.add(offset//word)
                            break
            if not ends:
                groups.append((TaintDependency('unknown', 'execve argv terminator correspondence unresolved', uncertain=True),))
                continue
            for slot in range(max(ends)):
                delta=p.constant(slot*word, p.type_of(argv), call.origin)
                address=p.operation(SymbolicOp.ADD, p.type_of(argv), (argv, delta), call.origin)
                read=ArgumentRead(word*8, e.architecture.endian, call.origin)
                for pointer in d.read(block, index, address, read, 0):
                    if d.guard_concrete(pointer)==0:continue
                    groups.append(self.buffer(block, index, pointer, call.origin))
        return self.union(groups)

    def analyze(self):
        accounting=self.port.engine.accounting
        previous=accounting.observer
        validate=self.port.validate_current
        def observer(dimension, observed):
            if previous is not None:previous(dimension, observed)
            self.check_query_clock()
            if dimension=='worklist_iterations' and self.query_work_limit is not None and observed>self.query_work_limit:
                raise DemandLimit('Independent memory worklist query share exhausted', dimension='query')
        def scoped_validate():
            validate()
            self.check_query_clock()
        accounting.observer=observer
        self.port.validate_current=scoped_validate
        try:
            try:return self._analyze()
            except (BudgetExceeded, DemandLimit, RecursionError) as error:return self.partial_summary(error)
        finally:
            self.clear_query_limits()
            accounting.observer=previous
            self.port.validate_current=validate

    def add_sink(self, sink):
        """Join requirements at the same original sink instead of path copies."""
        key=sink.function, sink.site, sink.name, sink.kind, sink.offsets, sink.origin, sink.constraints, sink.guards, sink.destinations, sink.weak_kind
        if key in self.sink_indices:
            index=self.sink_indices[key]
            previous=self.completed_sinks[index]
            self.completed_sinks[index]=replace(previous, dependencies=self.union((previous.dependencies, sink.dependencies)),
                length_dependencies=self.union((previous.length_dependencies, sink.length_dependencies)))
        else:
            self.sink_indices[key]=len(self.completed_sinks)
            self.completed_sinks.append(sink)

    def add_global_output(self, output, *, limited=False):
        key=global_output_order(output)
        previous=self.completed_global_outputs.get(key)
        self.completed_global_outputs[key]=output if previous is None else replace(previous,
            dependencies=tuple(sorted(set(previous.dependencies+output.dependencies), key=dependency_order)) if limited else
                self.union((previous.dependencies, output.dependencies)))

    def partial_summary(self, error):
        """A stopped frontier cannot erase completed flows or become clean."""
        if self.active_sink is not None:
            dependencies=tuple(sorted(self.partial_sources|self.query_sources, key=dependency_order))+(TaintDependency('unknown', 'Interrupted sink query remains incomplete', uncertain=True),)
            # Evidence preservation is allowed beyond the propagation budget:
            # it must not throw a second limit and erase the known frontier.
            self.completed_sinks.append(replace(self.active_sink, dependencies=dependencies))
        pending=tuple(self.pending)+tuple(self.diagnostics)+tuple(self.query_pending.values())+((self.frontier, type(error).__name__+': '+str(error)),)
        if self.active_global_output is not None:
            output=self.active_global_output
            key=global_output_order(output)
            previous=self.completed_global_outputs.get(key)
            known=set(self.query_sources)|set(self.partial_sources)|set(() if previous is None else previous.dependencies)
            self.completed_global_outputs[key]=replace(output, dependencies=tuple(sorted(known, key=dependency_order))+
                (TaintDependency('unknown', 'Interrupted global output query', uncertain=True),))
        return TaintProcedureSummary(self.base+self.function.function_id.rva,
            tuple(sorted(dict.fromkeys(self.completed_returns), key=dependency_order)), tuple(sorted(self.completed_outputs.items())),
            tuple(sorted(dict.fromkeys(sink for sink in self.completed_sinks if sink is not None), key=sink_order)), pending,
            tuple(sorted(self.table_state.outputs.items(), key=lambda item:repr(item[0]))),
            tuple(sorted(set(self.completed_scalar_returns), key=dependency_order))+(TaintDependency('unknown', 'Interrupted scalar-return analysis', uncertain=True),),
            tuple(self.completed_global_outputs[key] for key in sorted(self.completed_global_outputs)))

    def local_failure(self, error, origin):
        if isinstance(error, DemandLimit) and error.dimension=='query':raise error
        if isinstance(error, DemandLimit) and error.dimension not in ('alternatives', 'depth', 'query'):raise error
        self.pending.append((origin, type(error).__name__+': '+str(error)))
        return TaintDependency('unknown', 'Unresolved local frontier at '+origin+': '+str(error), uncertain=True)

    def query_schedule(self):
        """Prioritize known sink demands; each query keeps its real cutoff.

        This orders independent backward queries, never the program effects
        inspected by buffer/use-def. Exhaustion must not consistently starve
        callbacks behind earlier, unrelated expression products.
        """
        buckets=[[] for _ in range(5)]
        inherited=sum(len(self.summaries[callee].sinks) for _, _, call in self.calls.values()
            for callee in self.call_functions(call) if callee in self.summaries)
        local_first=inherited>self.max_dependencies
        for block in self.function.blocks:
            groups=[[] for _ in range(5)]
            for index, effect in enumerate(block.effects):
                priority=4
                if isinstance(effect, CallEffect):
                    rule=lookup(self.demand.call_name(effect))
                    local=rule and rule.operation in ('copy', 'format_output', 'format_input', 'command', 'command_argv')
                    if local_first and local:priority=0
                    elif any(self.summaries[f].sinks for f in self.call_functions(effect) if f in self.summaries):priority=2 if local_first else 0
                    elif rule and rule.operation=='hash_search':priority=1
                    elif rule and rule.operation in ('copy', 'format_output', 'format_input', 'command', 'command_argv'):priority=2
                    else:priority=3
                groups[priority].append((index, effect))
            for priority, group in enumerate(groups):
                if group:buckets[priority].append((block, tuple(group)))
        return tuple(item for bucket in buckets for item in bucket)

    def local_call_query(self, effect, block, index):
        d=self.demand
        p=self.port
        e=p.engine
        rule=lookup(d.call_name(effect))
        site=self.base+effect.site.point.instruction_rva
        if rule and rule.operation=='legacy_trace_source':
            self.pending.append((effect.origin,
                'Legacy SSL_read backward 0x100 trace has no Source ID; transfer not yet migrated'))
            return
        if rule and rule.operation=='format_output_va_list':
            _, unresolved=self.format_string_indexes(effect, rule)
            if unresolved:self.pending.append((effect.origin,
                'Legacy vsnprintf format/va_list correspondence remains incomplete'))
            return
        if rule and rule.operation=='hash_search':
            actions=self.constants(effect, (2,))
            roots=tuple(self.table_state.root(value, effect.origin) for value in self.argument(effect, 4))
            if actions!=(1,):
                for root in roots:
                    for retptr in self.argument(effect, 3):self.table_state.find(root, effect, retptr)
            if actions!=(0,):
                dependencies=self.union(self.buffer(block, index, value, effect.origin) for value in self.argument(effect, 1))
                for root in roots:self.table_state.write(root, dependencies, effect)
            if not actions:self.diagnostics.append('hsearch_r action unknown; FIND/INSERT retained as may at '+effect.origin)
        if rule and rule.operation in ('copy', 'format_output', 'format_input', 'command', 'command_argv'):
            slots=((rule.source,) if rule.source is not None else self.format_arguments(effect, rule))
            if rule.name=='_system':slots+=self.format_arguments(effect, rule)
            offsets=[]
            destination_requirements=[]
            destinations=(rule.destination,) if rule.destination is not None else self.format_arguments(effect, rule) if rule.operation=='format_input' else ()
            for slot in destinations:
                for value in self.argument(effect, slot):
                    sizes, requirements=self.destination(value, effect.origin)
                    offsets.extend(sizes)
                    destination_requirements.extend(requirements)
            constraints=self.constants(effect, rule.lengths)
            if rule.lengths and not constraints and rule.operation=='format_output':constraints=('S',)
            bounded=rule.operation=='copy' and bool(rule.lengths)
            self.active_sink=SinkRequirement(self.base+self.function.function_id.rva, site, rule.name,
                'command' if rule.operation in ('command', 'command_argv') else 'copy', tuple(sorted(set(offsets))),
                (), effect.origin, constraints, tuple(g.key for g in d.value(effect.guard)), tuple(sorted(set(destination_requirements), key=repr)),
                weak_kind='copy_length' if bounded else 'command' if rule.operation.startswith('command') else 'copy',
                length_dependencies=(TaintDependency('unknown', 'Length-taint analysis pending', uncertain=True),) if bounded else ())
            self.partial_sources=set()
            try:
                dependencies=(self.argv_dependencies(effect, block, index) if rule.operation=='command_argv' else
                    self.union(self.buffer(block, index, value, effect.origin)
                        for slot in slots for value in self.argument(effect, slot)))
            except DemandLimit as error:
                if error.dimension not in ('alternatives', 'depth'):raise
                # A local sink can discover valid Source identities before a
                # later path/guard alternative crosses the abstract-domain
                # cap.  Keep those input facts and an explicit upper-bound
                # Unknown instead of replacing the whole sink with Unknown.
                self.pending.append((effect.origin, 'Local sink binding incomplete: '+str(error)))
                known=tuple(sorted(self.partial_sources|self.query_sources, key=dependency_order))
                self.local_recoveries.append({'origin':effect.origin, 'stage':'buffer',
                    'known':len(known), 'kinds':dict(sorted(Counter(dep.kind for dep in known).items()))})
                dependencies=known+(TaintDependency('unknown',
                    'Local sink alternatives incomplete at '+effect.origin, uncertain=True),)
            dependencies=tuple(replace(dep, recipes=tuple(dict.fromkeys(dep.recipes+self.length_recipes(effect, rule))),
                unresolved_constraints=dep.unresolved_constraints or effect.origin in self.unresolved_recipe_calls) for dep in dependencies)
            if rule.format_index is not None and any('Unknown format at '+effect.origin==note.split(';')[0] for note in self.diagnostics):
                # The preceding conservative recovery may intentionally hold
                # more evidence rows than the propagation cap.  Appending an
                # Unknown is evidence preservation, not another data-flow
                # expansion, so it must not throw and erase the known Sources.
                dependencies=tuple(dict.fromkeys(dependencies+
                    (TaintDependency('unknown', 'Unknown format argument set', uncertain=True),)))
            self.active_sink=replace(self.active_sink, dependencies=dependencies)
            if bounded:
                try:
                    lengths=self.in_length_channel(lambda:self.length_taint(effect, rule, block, index))
                    bounds=uniform_copy_length_constraints(lengths)
                    self.active_sink=replace(self.active_sink, length_dependencies=lengths,
                        constraints=self.constraints(constraints, bounds))
                except DemandLimit as error:
                    if error.dimension not in ('alternatives', 'depth'):raise
                    self.pending.append((effect.origin, 'Local sink length binding incomplete: '+str(error)))
                    # in_length_channel records every length-only Source seen
                    # before the limit.  Do not replace that partial frontier
                    # with a bare Unknown here: doing so loses the exact fact
                    # that makes legacy bounded-copy weak propagation fire.
                    lengths=self.active_sink.length_dependencies
                    if not lengths:
                        lengths=(TaintDependency('unknown',
                            'Local sink length alternatives incomplete at '+effect.origin,
                            uncertain=True),)
                    elif not any(dep.kind=='unknown' for dep in lengths):
                        lengths=lengths+(TaintDependency('unknown',
                            'Local sink length alternatives incomplete at '+effect.origin,
                            uncertain=True),)
                    self.local_recoveries.append({'origin':effect.origin, 'stage':'length',
                        'buffer_dependencies':len(self.active_sink.dependencies),
                        'buffer_kinds':dict(sorted(Counter(dep.kind for dep in self.active_sink.dependencies).items())),
                        'length_dependencies':len(lengths),
                        'length_kinds':dict(sorted(Counter(dep.kind for dep in lengths).items()))})
                    self.active_sink=replace(self.active_sink, length_dependencies=lengths)
            self.local_recoveries.append({'origin':effect.origin, 'stage':'commit',
                'buffer_dependencies':len(self.active_sink.dependencies),
                'buffer_kinds':dict(sorted(Counter(dep.kind for dep in self.active_sink.dependencies).items()))})
            self.add_sink(self.active_sink)

    def execute_query(self, query):
        d=self.demand
        p=self.port
        e=p.engine
        effect=query.effect
        block=query.block
        index=query.index
        if isinstance(effect, (CallEffect, ReturnEffect)) and all(d.guard_concrete(value) is False for value in d.value(effect.guard)):
            self.active_sink=None
            return
        if query.kind=='source':
            rule=lookup(d.call_name(effect))
            if rule is None or rule.operation not in ('source_buffer', 'source_return'):
                raise ValueError('Source query has no active source rule')
            if rule.operation=='source_return':
                self.register_scalar_source_fact(effect)
                self.register_source_fact(effect, e.location(None, None, 8, e.architecture.endian, effect.origin), rule)
            else:
                for value in self.argument(effect, rule.destination):
                    location=self.procedure_region(effect, rule, value)
                    if location is not None:self.register_source_fact(effect, location, rule)
        elif query.kind=='call':self.local_call_query(effect, block, index)
        elif query.kind=='table':
            root, dependencies=query.payload
            roots=self.table_state.bind_roots(root, effect)
            # A table summary mixes known Source relations with optional
            # global/formal refinements. Commit the already proved Source
            # slice before an unrelated backward demand can exhaust the
            # function budget; partial_summary then retains those table facts.
            sources=tuple(dep for dep in dependencies if dep.kind=='source')
            others=tuple(dep for dep in dependencies if dep.kind!='source')
            try:
                for batch in (sources, others):
                    if not batch:continue
                    bound=self.bind_dependencies(batch, effect, block, index)
                    for target_root in roots:self.table_state.write(target_root, bound, effect)
            except (DemandLimit, BudgetExceeded, RecursionError) as error:
                # Preserve the omitted alternatives when the completed Source
                # slice is exported by partial_summary. This assignment must
                # remain usable after the normal union budget is exhausted.
                unknown=TaintDependency('unknown', 'Interrupted table binding at '+effect.origin+': '+str(error), uncertain=True)
                for target_root in roots:
                    previous=self.table_state.outputs.get(target_root, ())
                    self.table_state.outputs[target_root]=tuple(sorted(set(previous+(unknown,)), key=dependency_order))
                raise
        elif query.kind=='sink':
            self.active_sink=self.bind_sink(query.payload, effect, block, index)
            self.add_sink(self.active_sink)
        elif query.kind=='return':
            for reference in d.value(query.payload):self.completed_returns.extend(self.expression(reference, block, index, effect.origin))
        elif query.kind=='scalar_return':
            for reference in d.value(query.payload):self.completed_scalar_returns.extend(self.scalar_expression(reference, block, index, effect.origin))
        elif query.kind=='output':
            slot=query.payload
            reference=p.symbol('argument:'+str(slot), ValueType.bv(e.architecture.pointer_bits), effect.origin)
            dependencies=tuple(dep for dep in self.buffer(block, index, reference, effect.origin, whole_region=True,
                    export_root=e.argument_roots[slot].object_id)
                if not(dep.kind=='argument' and dep.value==slot and dep.offset is None))
            if dependencies:self.completed_outputs[slot]=self.union((self.completed_outputs.get(slot, ()), dependencies))
        elif query.kind=='global_output':
            from .global_outputs import query as query_global_output
            query_global_output(self, query.payload, block, index, effect.origin)
        else:raise ValueError('Unknown taint query kind '+query.kind)

    def _analyze(self):
        from .query_worklist import TaintQuery, run_queries
        queries=[]
        exits=[]
        def append(kind, block, index, effect, payload=None):
            queries.append(TaintQuery(str(len(queries))+':'+kind+':'+effect.origin, kind, block, index, effect, payload))
        # The old procedure executes at its callsite even if no later sink
        # demands the buffer. Register the initial fact before demand queries;
        # the ordinary use/def cutoff still controls where it can propagate.
        for block in self.function.blocks:
            for index, effect in enumerate(block.effects):
                if not isinstance(effect, CallEffect):continue
                rule=lookup(self.demand.call_name(effect))
                if rule and rule.operation in ('source_buffer', 'source_return'):
                    append('source', block.id, index, effect)
        for block, effects in self.query_schedule():
            for index, effect in effects:
                if isinstance(effect, ReturnEffect):exits.append((block.id, index, effect))
                if not isinstance(effect, CallEffect):continue
                append('call', block.id, index, effect)
                for callee in self.call_functions(effect):
                    summary=self.summaries.get(callee)
                    if summary is None:continue
                    for item in summary.tables:append('table', block.id, index, effect, item)
                    for sink in summary.sinks:append('sink', block.id, index, effect, sink)
        for block, index, effect in exits:
            for value in effect.values:append('return', block, index, effect, value)
            for value in effect.values:append('scalar_return', block, index, effect, value)
            for slot in getattr(self.port.engine, 'argument_roots', {}):append('output', block, index, effect, slot)
            from .global_outputs import definitions as global_definitions
            for definition in global_definitions(self):append('global_output', block, index, effect, definition)
        run_queries(self, queries)
        return TaintProcedureSummary(self.base+self.function.function_id.rva, self.union((self.completed_returns,)),
            tuple(sorted(self.completed_outputs.items())),
            tuple(sorted(dict.fromkeys(sink for sink in self.completed_sinks if sink is not None), key=sink_order)),
            tuple(self.pending)+tuple(self.diagnostics)+tuple(self.query_pending.values()),
            tuple(sorted(self.table_state.outputs.items(), key=lambda item:repr(item[0]))),
            self.union((self.completed_scalar_returns,)),
            tuple(self.completed_global_outputs[key] for key in sorted(self.completed_global_outputs)))
