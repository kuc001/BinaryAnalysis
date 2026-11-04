"""CIR ports of old backward use/def and procedure taint requirements.

Dependencies are detached source/argument/global descriptors. Memory alias
decisions stay in MemoryQueryPort; unknown correspondence remains explicit.
This pass produces may-flow requirements, not concrete vulnerability proofs.
"""
from dataclasses import replace
from collections import Counter, deque
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
from emtaint.analysis.dataflow.demand_index import FunctionDemandIndex
from emtaint.analysis.dataflow.demand_address import DemandAddressNormalizer
from emtaint.analysis.dataflow.demand_register import RegisterSliceResolver
from emtaint.analysis.dataflow.demand_loop import LegacyLoopSummarizer
from emtaint.analysis.dataflow.demand_query import (
    DemandQueryResult,
    DemandQueryRunner,
)
from emtaint.analysis.taint.regions import RegionTaintTracker
from emtaint.procedures.legacy import ProcedureRule, lookup, legacy_format_parameters
from emtaint.memory.policies import BudgetExceeded
from emtaint.analysis.taint.guards import (
    arm_unsigned_hi,
    arm_zero_flag_equal,
    legacy_constraint,
    unit_product_arguments,
)
from emtaint.analysis.framework.summaries import compile_recipe
from emtaint.procedures.legacy import legacy_integer_constraints, uniform_copy_length_constraints
from emtaint.analysis.taint.tables import LegacyHashTables
from emtaint.analysis.taint.subsumption import source_antichain
from emtaint.analysis.taint.definition_frontier import DefinitionFrontierCache
from emtaint.analysis.taint.global_outputs import (
    location as global_output_location,
    output_order as global_output_order,
)
from emtaint.analysis.taint.facts import ScalarTaintFact
from emtaint.analysis.taint.demand_budget import (
    LOCAL_SINK_OPERATIONS,
    QueryBudgetController,
)
from emtaint.analysis.taint.demand_binding import DemandBinding
from emtaint.analysis.taint.demand_memory import DemandMemory
from emtaint.analysis.taint.demand_procedures import DemandProcedures
from emtaint.analysis.taint.demand_models import (
    BufferDestination,
    ConstraintRecipe,
    DeferredFormatArgument,
    SinkRequirement,
    TaintDependency,
    TaintProcedureSummary,
    dependency_order,
    sink_order,
)


MAX_RECURSION_DEPTH = 120
MAX_RECIPE_NODES = 256
MAX_DAG_COPY_DEPTH = 12
RECURRENCE_CACHE_LIMIT = 4096
DEFINITION_CACHE_LIMIT = 8192
DEFAULT_MAX_DEPENDENCIES = 256


class ProcedureDemand(LegacyDemand):
    """Resolve scalar and memory use/def requirements for one CIR procedure.

    The class adds immutable-index and definition-frontier caches around the
    legacy demand engine.  Cache entries are scoped to the procedure's CIR,
    initial memory version, and object facts; query-local cycle placeholders
    are never promoted into shared completed values.
    """

    def __init__(self, function, port, cfg, initial, *, budget=DemandBudget(),
                 summaries=None, names=None, cache_queries=True):
        self.reaching_cache={}
        self.reaching_cache_hits=0
        self.reaching_cache_misses=0
        self.definition_cache={}
        self.definition_cache_hits=0
        self.definition_cache_misses=0
        self.recurrence_cache={}
        self.recurrence_cache_hits=0
        self.query_scalar_limit=None
        super().__init__(function, port, cfg, initial, budget=budget,
                         summaries=summaries)
        self.function_index=FunctionDemandIndex.build(function, cfg)
        self.address_normalizer=DemandAddressNormalizer(self)
        self.register_slices=RegisterSliceResolver(self)
        self.loop_summarizer=LegacyLoopSummarizer(self)
        self.query_runner=DemandQueryRunner(
            self, (DemandLimit, BudgetExceeded, RecursionError))
        self.names=dict(names or {})
        self.return_calls={}
        self.cache_queries=cache_queries
        self.binding_cache={}
        self.binding_cache_hits=0
        self.binding_cache_misses=0
        self.summary_call_reachability={}
        self.frontiers=DefinitionFrontierCache(self)
        self.predecessors={
            block:tuple(sorted(
                values, key=lambda item:(item.rva, item.index, item.mode)))
            for block, values in self.predecessors.items()
        }

    def guard_concrete(self, reference):return self.port.guard_concrete(reference)

    def tick(self, depth):
        super().tick(depth)
        if self.query_scalar_limit is not None and self.steps>self.query_scalar_limit:
            raise DemandLimit('Independent scalar query share exhausted', dimension='query')

    def reaching(self, block, index, name):
        key=block, index, name
        if self.cache_queries and key in self.reaching_cache:
            self.tick(0)
            self.reaching_cache_hits+=1
            return self.reaching_cache[key]
        self.reaching_cache_misses+=1
        definitions, entry=self.function_index.reaching(
            block, index, name, on_visit=lambda:self.tick(0))
        result=frozenset(definitions), entry
        if self.cache_queries:self.reaching_cache[key]=result
        return result

    def definition_cutoff(self, block, index, name):
        """Use the immutable body index for the legacy cutoff contract."""
        return self.function_index.definition_cutoff(block, index, name)

    def resolve_value(self, operand)->DemandQueryResult:
        """Resolve one top-level value with explicit incomplete semantics.

        Query-local cycle placeholders are discarded after the query.  Only
        completed values already admitted to the ordinary legacy memo remain
        shared.  The function-level step ceiling and all MemoryQueryPort
        accounting continue to apply.
        """
        return self.query_runner.resolve_value(operand)

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
        if (self.cache_queries and base_key not in self.memo and
                len(self.recurrence_cache)<RECURRENCE_CACHE_LIMIT
                and not any(self.contains(value, outer) for value in result)):
            self.recurrence_cache[key]=result
        return result

    def linear_register(self, operand, name, seen=frozenset()):
        """Delegate legacy affine register parsing to the loop component."""
        return self.loop_summarizer.linear_register(operand, name, seen)

    def increments(self, name, width):
        """Delegate legacy increment discovery to the loop component."""
        return self.loop_summarizer.increments(name, width)

    def induction(self, block, index, name, width, depth):
        """Delegate legacy DDG induction without changing its abstraction."""
        return self.loop_summarizer.induction(
            block, index, name, width, depth)

    def affine(self, reference, variable):
        """Delegate SSE affine projection used by legacy table paths."""
        return self.loop_summarizer.affine(reference, variable)

    def memory_definitions(self, block, index, loc, load, seen, depth):
        if (not self.cache_queries or
                self.reaching_summary_store(block, index)):
            return super().memory_definitions(block, index, loc, load, seen, depth)
        e=self.port.engine
        key=(block, index, loc.id.scope, loc.object_id, loc.offset_lower, loc.offset_upper, loc.width_bits,
            loc.endian, loc.address_space, loc.origin, loc.assessment, load.origin, load.width_bits, load.endian,
            self.initial.memory, tuple(e.object_facts.items()))
        if key in self.definition_cache:
            self.tick(depth)
            self.definition_cache_hits+=1
            return self.definition_cache[key]
        self.definition_cache_misses+=1
        result=self.frontiers.query(block, index, loc, load, seen, depth)
        if (len(self.definition_cache)<DEFINITION_CACHE_LIMIT and
                not any(self.contains(value, self.cycles)
                        for value in result[0])):
            self.definition_cache[key]=result
        return result

    def reaching_summary_store(self, block, index):
        """Return whether a modeled callee Store can precede this query."""
        key=block, index
        if key in self.summary_call_reachability:
            return self.summary_call_reachability[key]
        pending=[key]
        visited=set()
        found=False
        while pending and not found:
            current, cutoff=pending.pop()
            if (current, cutoff) in visited:continue
            visited.add((current, cutoff))
            for effect in self.blocks[current].effects[:cutoff]:
                if not isinstance(effect, CallEffect) or not isinstance(effect.target, DirectTarget):continue
                summary=self.summaries.get(effect.target.function)
                if summary is not None and getattr(summary, 'stores', ()):
                    found=True
                    break
            if not found:
                pending.extend((predecessor, len(self.blocks[predecessor].effects))
                    for predecessor in self.predecessors[current])
        self.summary_call_reachability[key]=found
        return found

    def address_binding(self, reference, seen=frozenset()):
        if not self.cache_queries or seen:
            binding=super().address_binding(reference, seen)
            return (binding if binding is not None else
                    self.address_normalizer.entry_stack_binding(reference))
        if reference in self.binding_cache:
            self.binding_cache_hits+=1
        else:
            self.binding_cache_misses+=1
            binding=super().address_binding(reference, seen)
            if binding is None:
                binding=self.address_normalizer.entry_stack_binding(reference)
            self.binding_cache[reference]=binding
        return self.binding_cache[reference]

    def demand_metrics(self)->dict[str, int]:
        """Return cache/query counters without changing analysis state."""
        metrics={
            'function_effects':self.function_index.effect_count,
            'reaching_cache_entries':len(self.reaching_cache),
            'reaching_cache_hits':self.reaching_cache_hits,
            'reaching_cache_misses':self.reaching_cache_misses,
            'definition_cache_entries':len(self.definition_cache),
            'definition_cache_hits':self.definition_cache_hits,
            'definition_cache_misses':self.definition_cache_misses,
            'frontier_cache_entries':len(self.frontiers.cache),
            'frontier_cache_hits':self.frontiers.hits,
            'frontier_cache_misses':self.frontiers.misses,
            'recurrence_cache_entries':len(self.recurrence_cache),
            'recurrence_cache_hits':self.recurrence_cache_hits,
            'binding_cache_entries':len(self.binding_cache),
            'binding_cache_hits':self.binding_cache_hits,
            'binding_cache_misses':self.binding_cache_misses,
        }
        metrics.update(self.query_runner.metrics())
        return metrics

    def exact_stack_address(
            self, operand: Constant | ValueRef, seen: frozenset[str] = frozenset()
    ) -> tuple[AccessRoot, int | None] | None:
        """Project a copied constant offset from an unchanged entry SP for an exact stack query."""
        proof=self.address_normalizer.exact_stack_address(operand, seen)
        return None if proof is None else proof.binding

    def call_name(self, call):
        symbol=(call.target.symbol
            if isinstance(call.target, ExternalTarget) else '')
        return self.names.get(call.site.point.instruction_rva, symbol)

    def exact_slice_before(self, block:BlockId, index:int, source:RegisterSlice,
                           depth:int, seen:frozenset=frozenset())->tuple:
        """Follow only full-coverage slice definitions; preserve each CFG alternative.

        An overlapping write with different geometry falls back to Unknown.
        This P7 refinement leaves P6 whole-register demand unchanged.
        """
        return self.register_slices.exact_before(
            block, index, source, depth, seen)

    def exact_slice_definition(self, block:BlockId, cutoff:int, source:RegisterSlice,
                               depth:int, seen:frozenset)->tuple:
        return self.register_slices.exact_definition(
            block, cutoff, source, depth, seen)

    def full_slice_fallback(self, block:BlockId, index:int, source:RegisterSlice,
                            depth:int)->tuple:
        return self.register_slices.full_fallback(
            block, index, source, depth)

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
    """Behavior-compatible facade for P7 interprocedural taint demand.

    Mutable analysis state remains on this object.  Domain components receive
    it through structural owner protocols and implement Caller binding, memory
    traversal, and procedure modeling without owning a separate session.
    Incomplete, budgeted, and unknown results remain explicit may evidence.
    """

    def __init__(self, function, port, cfg, initial, *, names=None, summaries=None, targets=None, image_base=0,
                 max_steps=250000,
                 max_dependencies=DEFAULT_MAX_DEPENDENCIES,
                 cache_queries=True, tables=None, function_deadline=None):
        self.function=function
        self.port=port
        self.cfg=cfg
        self.base=image_base
        self.demand=ProcedureDemand(
            function, port, cfg, initial,
            budget=DemandBudget(
                steps=500000,
                alternatives=MAX_RECIPE_NODES,
                depth=MAX_RECURSION_DEPTH,
            ),
            names=names,
            cache_queries=cache_queries,
        )
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
        self.calls={
            effect.origin:(block.id, index, effect)
            for block in function.blocks
            for index, effect in enumerate(block.effects)
            if isinstance(effect, CallEffect)
        }
        self.load_positions={
            effect.origin:(block.id, index)
            for block in function.blocks
            for index, effect in enumerate(block.effects)
            if isinstance(effect, LoadEffect)
        }
        self.local_sink_call_count=sum(bool(
            rule and rule.operation in LOCAL_SINK_OPERATIONS)
            for _, _, call in self.calls.values() for rule in (lookup(self.demand.call_name(call)),))
        self.inherited_sink_count=sum(len(self.summaries[callee].sinks)
            for _, _, call in self.calls.values() for callee in self.call_functions(call) if callee in self.summaries)
        self.budget_controller=QueryBudgetController(self)
        self._binding=DemandBinding(self)
        self._memory=DemandMemory(self)
        self._procedures=DemandProcedures(self)

    def tick(self):
        self.port.validate_current()
        self.steps+=1
        if self.steps>self.max_steps:
            raise DemandLimit(
                'Taint requirement worklist budget; unresolved dependencies '
                'remain')
        if self.query_step_limit is not None and self.steps>self.query_step_limit:
            raise DemandLimit(
                'Independent taint query share exhausted; later queries '
                'retain remaining global budget', dimension='query')

    def begin_query(self, query=None):
        """Delegate query-share calculation while preserving this API."""
        self.budget_controller.begin_query(query)

    def clear_query_limits(self):
        """Delegate query-limit cleanup while preserving this API."""
        self.budget_controller.clear_query_limits()

    def check_query_clock(self):
        """Delegate the historical wall-share check."""
        self.budget_controller.check_query_clock()

    def observe_sources(self, dependencies):
        return self._binding.observe_sources(dependencies)

    def union(self, groups):
        return self._binding.union(groups)

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
        with self.budget_controller.argument_preparation(
                call, index) as preparation:
            try:
                return self._argument(call, index)
            except DemandLimit as error:
                preparation['status']='incomplete'
                if error.dimension=='query':
                    raise
                self.local_failure(error, call.origin)
                type_=(call.arguments[index].type
                    if index<len(call.arguments) else
                    ValueType.bv(
                        self.port.engine.architecture.pointer_bits))
                return (self.port.unknown(type_, call.origin,
                    'Unresolved call argument '+str(index)+': '+str(error)),)
            except (BudgetExceeded, RecursionError):
                preparation['status']='incomplete'
                raise

    def _argument(self, call, index):
        if index<len(call.arguments):return self.demand.value(call.arguments[index])
        count=len(call.abi.argument_registers or ('r0', 'r1', 'r2', 'r3'))
        if index<count:
            return (self.port.unknown(
                ValueType.bv(self.port.engine.architecture.pointer_bits),
                call.origin,
                'Unavailable call argument'),)
        return self.demand.stack_argument(call, index-count, self.port.engine.architecture.pointer_bits, 0)

    def location(self, reference, origin):
        return self._memory.location(reference, origin)

    def _location(self, reference, origin):
        return self._memory._location(reference, origin)

    def constants(self, call, indices):
        groups=[{self.demand.guard_concrete(v) for v in self.argument(call, i)} for i in indices]
        if not groups:return ()
        if all(len(g)==1 and type(next(iter(g))) is int for g in groups):
            value=1
            for group in groups:value*=next(iter(group))
            return (value,)
        return ()

    def procedure_region(self, call, rule, reference):
        return self._memory.procedure_region(call, rule, reference)

    def path_guards(self, call):
        return self._binding.path_guards(call)

    def guarded_length_guards(self, call, recipes: tuple) -> tuple:
        return self._binding.guarded_length_guards(call, recipes)

    @staticmethod
    def constraints(*groups):
        values=[v for group in groups for v in group]
        numbers=[v for v in values if type(v) is int and v not in (0, 1)]
        booleans=tuple(sorted({
            value for value in values
            if type(value) is int and value in (0, 1)
        }))
        numeric=() if not numbers else (min(numbers),)
        symbolic=tuple(sorted({
            value for value in values if type(value) is str
        }))
        return booleans+numeric+symbolic

    def length_recipes(self, call, rule):
        return self._binding.length_recipes(call, rule)

    def _length_recipes(self, call, rule):
        return self._binding._length_recipes(call, rule)

    def bind_constraints(self, dependency, call):
        return self._binding.bind_constraints(dependency, call)

    def register_source_fact(self, call:CallEffect, location:MemoryLocation, rule:ProcedureRule)->None:
        return self._binding.register_source_fact(call, location, rule)

    def register_scalar_source_fact(self, call:CallEffect)->ScalarTaintFact|None:
        return self._binding.register_scalar_source_fact(call)

    def source(self, call, location, rule):
        return self._binding.source(call, location, rule)

    @staticmethod
    def union_handles(groups):return tuple(sorted(set(value for group in groups for value in group), key=repr))

    def handle(self, reference, seen=frozenset()):
        return self._binding.handle(reference, seen)

    def bind_handles(self, handles, call):
        return self._binding.bind_handles(handles, call)

    def call_functions(self, call):
        if isinstance(call.target, DirectTarget):return (self.base+call.target.function.rva,)
        return tuple(self.targets.get(self.base+call.site.point.instruction_rva, ()))

    def import_source(self, dependency, call, location=None):
        return self._binding.import_source(dependency, call, location)

    def _inherit_dependency_metadata(
            self, value, formal, site_guards):
        return self._binding._inherit_dependency_metadata(value, formal, site_guards)

    def _bind_deferred_format_argument(
            self, selector, formal, call, block, index, location, scalar):
        return self._binding._bind_deferred_format_argument(selector, formal, call, block, index, location, scalar)

    def _project_bound_source(
            self, dependency, call, site, site_guards):
        return self._binding._project_bound_source(dependency, call, site, site_guards)

    def _bind_one_dependency(
            self, dependency, call, block, index, location, scalar,
            site_guards):
        return self._binding._bind_one_dependency(dependency, call, block, index, location, scalar, site_guards)

    def bind_dependencies(self, dependencies, call, block, index,
                          location=None, *, scalar=False):
        return self._binding.bind_dependencies(dependencies, call, block, index, location, scalar=scalar)

    def expression(self, reference, block, index, origin):
        return self._binding.expression(reference, block, index, origin)

    def scalar_expression(self, reference, block, index, origin):
        return self._binding.scalar_expression(reference, block, index, origin)

    def length_taint(self, call, rule, block, index):
        return self._binding.length_taint(call, rule, block, index)

    def in_length_channel(self, operation):
        return self._binding.in_length_channel(operation)

    def destination(self, reference, origin):
        return self._memory.destination(reference, origin)

    def bind_sink(self, sink, call, block, index):
        return self._binding.bind_sink(sink, call, block, index)

    def _expression(self, reference, block, index, origin):
        return self._binding._expression(reference, block, index, origin)

    def token_dependencies(self, call, block, index):
        return self._procedures.token_dependencies(call, block, index)

    def edge_policy(self, predecessor, successor, location):
        return self._memory.edge_policy(predecessor, successor, location)

    def _normalize_buffer_location(
            self, reference, origin, whole_region, width_bits):
        return self._memory._normalize_buffer_location(reference, origin, whole_region, width_bits)

    def _scan_store_effect(
            self, effect, location, current, position, byte_access, result):
        return self._memory._scan_store_effect(effect, location, current, position, byte_access, result)

    def _scan_callee_memory_outputs(
            self, effect, current, position, location, export_root, result):
        return self._memory._scan_callee_memory_outputs(effect, current, position, location, export_root, result)

    def _scan_procedure_call_effect(
            self, effect, current, position, reference, location,
            export_root, result):
        return self._memory._scan_procedure_call_effect(
            effect, current, position, reference, location, export_root,
            result)

    def _scan_procedure_copy_sources(
            self, effect, rule, current, position, alias, result):
        return self._memory._scan_procedure_copy_sources(effect, rule, current, position, alias, result)

    def _entry_buffer_dependencies(
            self, location, reference, block, index, origin, whole_region,
            width_bits, byte_access, result):
        return self._memory._entry_buffer_dependencies(
            location, reference, block, index, origin, whole_region,
            width_bits, byte_access, result)

    def _enqueue_buffer_predecessors(
            self, frontier, location, todo):
        return self._memory._enqueue_buffer_predecessors(frontier, location, todo)

    def _decorate_frontier_dependencies(self, result, start, frontier):
        return self._memory._decorate_frontier_dependencies(result, start, frontier)

    def buffer(self, block, index, reference, origin, *, whole_region=False,
               width_bits=8, byte_access=False, export_root=None):
        return self._memory.buffer(
            block, index, reference, origin, whole_region=whole_region,
            width_bits=width_bits, byte_access=byte_access,
            export_root=export_root)

    def format_arguments(self, call, rule):
        return self._procedures.format_arguments(call, rule)

    def _format_arguments(self, call, rule):
        return self._procedures._format_arguments(call, rule)

    def format_string_indexes(self, call, rule):
        return self._procedures.format_string_indexes(call, rule)

    def _format_string_indexes(self, call, rule):
        return self._procedures._format_string_indexes(call, rule)

    def format_value_indexes(self, addresses, origin, *, diagnose=True):
        return self._procedures.format_value_indexes(addresses, origin, diagnose=diagnose)

    def _resolve_va_list_bases(self, call, rule, trace, groups):
        return self._procedures._resolve_va_list_bases(call, rule, trace, groups)

    def _collect_va_list_store_candidates(
            self, base, block, index, string_indexes, format_slots, trace):
        return self._procedures._collect_va_list_store_candidates(
            base, block, index, string_indexes, format_slots, trace)

    def _read_va_list_dependencies(
            self, addresses, call, block, index, read, string_indexes,
            format_unresolved, format_slots, trace, groups):
        return self._procedures._read_va_list_dependencies(
            addresses, call, block, index, read, string_indexes,
            format_unresolved, format_slots, trace, groups)

    def va_list_dependencies(self, call, block, index, rule):
        return self._procedures.va_list_dependencies(call, block, index, rule)

    def argv_dependencies(self, call, block, index):
        return self._procedures.argv_dependencies(call, block, index)

    def analyze(self):
        with self.budget_controller.query_lifecycle():
            try:return self._analyze()
            except (BudgetExceeded, DemandLimit, RecursionError) as error:return self.partial_summary(error)

    def add_sink(self, sink):
        """Join requirements at the same original sink instead of path copies."""
        key=(sink.function, sink.site, sink.name, sink.kind, sink.offsets,
            sink.origin, sink.constraints, sink.guards, sink.destinations,
            sink.weak_kind)
        if key in self.sink_indices:
            index=self.sink_indices[key]
            previous=self.completed_sinks[index]
            self.completed_sinks[index]=replace(
                previous,
                dependencies=self.union((
                    previous.dependencies, sink.dependencies)),
                length_dependencies=self.union((
                    previous.length_dependencies,
                    sink.length_dependencies)),
            )
        else:
            self.sink_indices[key]=len(self.completed_sinks)
            self.completed_sinks.append(sink)

    def add_global_output(self, output, *, limited=False):
        key=global_output_order(output)
        previous=self.completed_global_outputs.get(key)
        self.completed_global_outputs[key]=output if previous is None else replace(previous,
            dependencies=(tuple(sorted(
                set(previous.dependencies+output.dependencies),
                key=dependency_order)) if limited else
                self.union((previous.dependencies, output.dependencies))))

    def partial_summary(self, error):
        """A stopped frontier cannot erase completed flows or become clean."""
        if self.active_sink is not None:
            known=tuple(sorted(
                self.partial_sources|self.query_sources,
                key=dependency_order))
            dependencies=known+(TaintDependency(
                'unknown', 'Interrupted sink query remains incomplete',
                uncertain=True),)
            # Evidence preservation is allowed beyond the propagation budget:
            # it must not throw a second limit and erase the known frontier.
            self.completed_sinks.append(replace(self.active_sink, dependencies=dependencies))
        pending=(tuple(self.pending)+tuple(self.diagnostics)+
            tuple(self.query_pending.values())+
            ((self.frontier, type(error).__name__+': '+str(error)),))
        if self.active_global_output is not None:
            output=self.active_global_output
            key=global_output_order(output)
            previous=self.completed_global_outputs.get(key)
            known=(set(self.query_sources)|set(self.partial_sources)|
                set(() if previous is None else previous.dependencies))
            self.completed_global_outputs[key]=replace(output, dependencies=tuple(sorted(known, key=dependency_order))+
                (TaintDependency('unknown', 'Interrupted global output query', uncertain=True),))
        returns=tuple(sorted(
            dict.fromkeys(self.completed_returns), key=dependency_order))
        sinks=tuple(sorted(dict.fromkeys(
            sink for sink in self.completed_sinks if sink is not None),
            key=sink_order))
        tables=tuple(sorted(
            self.table_state.outputs.items(),
            key=lambda item:repr(item[0])))
        scalar_returns=tuple(sorted(
            set(self.completed_scalar_returns), key=dependency_order))
        scalar_returns+=(TaintDependency(
            'unknown', 'Interrupted scalar-return analysis',
            uncertain=True),)
        global_outputs=tuple(
            self.completed_global_outputs[key]
            for key in sorted(self.completed_global_outputs))
        return TaintProcedureSummary(
            self.base+self.function.function_id.rva,
            returns,
            tuple(sorted(self.completed_outputs.items())),
            sinks,
            pending,
            tables,
            scalar_returns,
            global_outputs,
        )

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
                    local=bool(
                        rule and rule.operation in LOCAL_SINK_OPERATIONS)
                    if local_first and local:priority=0
                    elif any(
                            self.summaries[function].sinks
                            for function in self.call_functions(effect)
                            if function in self.summaries):
                        priority=2 if local_first else 0
                    elif rule and rule.operation=='hash_search':priority=1
                    elif rule and rule.operation in LOCAL_SINK_OPERATIONS:
                        priority=2
                    else:priority=3
                groups[priority].append((index, effect))
            for priority, group in enumerate(groups):
                if group:buckets[priority].append((block, tuple(group)))
        return tuple(item for bucket in buckets for item in bucket)

    def _query_hash_call(self, effect, rule, block, index):
        return self._procedures._query_hash_call(effect, rule, block, index)

    def _local_sink_shape(self, effect, rule, site):
        return self._procedures._local_sink_shape(effect, rule, site)

    def _resolve_local_sink_dependencies(
            self, effect, rule, block, index, slots):
        return self._procedures._resolve_local_sink_dependencies(effect, rule, block, index, slots)

    def _resolve_local_sink_lengths(
            self, effect, rule, block, index, constraints):
        return self._procedures._resolve_local_sink_lengths(effect, rule, block, index, constraints)

    def _commit_local_sink(self, effect):
        return self._procedures._commit_local_sink(effect)

    def local_call_query(self, effect, block, index):
        return self._procedures.local_call_query(effect, block, index)

    def execute_query(self, query):
        d=self.demand
        p=self.port
        e=p.engine
        effect=query.effect
        block=query.block
        index=query.index
        if (isinstance(effect, (CallEffect, ReturnEffect)) and
                all(d.guard_concrete(value) is False
                    for value in d.value(effect.guard))):
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
                unknown=TaintDependency(
                    'unknown',
                    'Interrupted table binding at '+effect.origin+': '+
                    str(error),
                    uncertain=True,
                )
                for target_root in roots:
                    previous=self.table_state.outputs.get(target_root, ())
                    self.table_state.outputs[target_root]=tuple(sorted(set(previous+(unknown,)), key=dependency_order))
                raise
        elif query.kind=='sink':
            self.active_sink=self.bind_sink(query.payload, effect, block, index)
            self.add_sink(self.active_sink)
        elif query.kind=='return':
            for reference in d.value(query.payload):
                self.completed_returns.extend(self.expression(
                    reference, block, index, effect.origin))
        elif query.kind=='scalar_return':
            for reference in d.value(query.payload):
                self.completed_scalar_returns.extend(self.scalar_expression(
                    reference, block, index, effect.origin))
        elif query.kind=='output':
            slot=query.payload
            reference=p.symbol('argument:'+str(slot), ValueType.bv(e.architecture.pointer_bits), effect.origin)
            dependencies=tuple(dep for dep in self.buffer(block, index, reference, effect.origin, whole_region=True,
                    export_root=e.argument_roots[slot].object_id)
                if not(dep.kind=='argument' and dep.value==slot and dep.offset is None))
            if dependencies:
                self.completed_outputs[slot]=self.union((
                    self.completed_outputs.get(slot, ()), dependencies))
        elif query.kind=='global_output':
            from .global_outputs import query as query_global_output
            query_global_output(self, query.payload, block, index, effect.origin)
        else:raise ValueError('Unknown taint query kind '+query.kind)

    def _analyze(self):
        from .query_worklist import TaintQuery, run_queries
        queries=[]
        exits=[]
        def append(kind, block, index, effect, payload=None):
            queries.append(TaintQuery(
                str(len(queries))+':'+kind+':'+effect.origin,
                kind, block, index, effect, payload))
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
