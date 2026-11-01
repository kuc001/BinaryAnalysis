"""M-01..M-12 contract checks and explicit P5 runtime expectations.

No reference interpreter is substituted for the unimplemented memory engine.
"""
from dataclasses import replace
import time

from emtaint.core import (Completeness, ContextId, MemoryObject, MemoryObjectId, Endian)
from emtaint.core.contracts import (Assessment, Precision, UnsupportedSemantics, ValueType,
    SymbolicExprId, MemoryVersionId, MemoryLocationId, AccessPathId, AccessGraphId,
    Constant, SemanticBudgets)
from emtaint.memory import (AccessPath, Offset, Deref, APGNode, APGEdge, APGSummary,
    AccessGraph, MemoryLocation, InitialMemory, MemoryVersion, WriteMemory, ReadMemory,
    JoinMemory, JoinInput, HavocMemory, SymbolicNode, SymbolicOp, TaintFact,
    AliasResult, AliasKind, UpdateKind, select_update_policy, MemorySnapshot, modular_offset)
from emtaint.memory.query_port import UnimplementedMemoryQueryPort, QueryBudget
from emtaint.ir.canonical import (UnknownEffect, HavocEffect, StoreEffect, RegisterSlice,
    WriteRegister, RegisterWritePolicy, CallEffect, ExternalTarget, CallFootprint)
from emtaint.ir.canonical.wire import dumps, loads
from emtaint.solver.port import SolverResult, SolverStatus
from emtaint.solver.lowering import UnimplementedSolverLowering, LoweringRequest, LoweringStatus
from test_p3_contracts import fixture, sample_module


def expect_error(kind, operation):
    try:
        operation()
    except kind:
        return
    raise AssertionError('Expected explicit ' + kind.__name__)


def snapshot_fixture():
    _, _, _, origin, scope, arch, root, _, _, _ = fixture()
    x, truth = SymbolicExprId(scope, 'x'), SymbolicExprId(scope, 'true')
    r0, r1 = SymbolicExprId(scope, 'read-before'), SymbolicExprId(scope, 'read-after')
    m0, m1 = MemoryVersionId(scope, 'M0'), MemoryVersionId(scope, 'M1')
    loc = MemoryLocation(MemoryLocationId(scope, 'value'), root.object_id, 0, 0, 32,
                         Endian.LITTLE, 'default', 'o0')
    unknown_alias = AliasResult(AliasKind.UNKNOWN, (), Assessment())
    versions = (MemoryVersion(m0, InitialMemory('o0')),
        MemoryVersion(m1, WriteMemory(m0, loc.id, x, truth, UpdateKind.WEAK, unknown_alias, 'o0')))
    exprs = (SymbolicNode(x, ValueType.bv(32), SymbolicOp.SYMBOL, (), 'o0', 'x'),
             SymbolicNode(truth, ValueType.boolean(), SymbolicOp.CONSTANT, (), 'o0', True),
             SymbolicNode(r0, ValueType.bv(32), SymbolicOp.MEMORY_READ, (), 'o0', state=m0, location=loc.id),
             SymbolicNode(r1, ValueType.bv(32), SymbolicOp.MEMORY_READ, (), 'o0', state=m1, location=loc.id))
    path = AccessPath(AccessPathId(scope, 'p.value'), root, (Offset(0), Deref(32, 32, Endian.LITTLE)),
                      32, Endian.LITTLE, 'o0')
    summary = APGSummary('next', 'next', (Offset(8), Deref(32, 32, Endian.LITTLE)), 0, None,
        origin.point, 'Recursive field fixture', 'Declared next* superset; P5 coverage checker not implemented',
        'Field-depth distinctions merged')
    abstract = Assessment(precision=Precision.OVER_APPROX, precision_loss=('Recursive field summary',),
                           diagnostics=('Summary soundness has not been verified',))
    graph = AccessGraph(AccessGraphId(scope, 'next-star'),
        (APGNode('root', root), APGNode('next'), APGNode('data')),
        (APGEdge('root', 'next', Offset(0)), APGEdge('next', 'data', Offset(0))), (summary,),
        ('root',), ('data',), abstract)
    fact = TaintFact('may-taint', root, None, graph.id, scope.context, m1, truth,
        'source-candidate', 'o0', ('Source(arg)', 'arg.next*.data', 'Sink candidate'), abstract)
    return MemorySnapshot(scope, arch, (origin,), (MemoryObject(root.object_id, 'argument fixture', 8),),
        (path,), (graph,), (loc,), versions,
        (ReadMemory(m0, loc.id, r0, truth, 'o0'), ReadMemory(m1, loc.id, r1, truth, 'o0')),
        exprs, (fact,))


def m01(snapshot):
    path = snapshot.paths[0]
    address = replace(path, segments=(Offset(8),))
    deref = replace(path, segments=(Offset(8), Deref(32, 32, Endian.LITTLE)))
    assert address.deref_count == 0 and deref.deref_count == 1 and address != deref
    assert loads(dumps(deref)) == deref


def m02(snapshot):
    function, context = snapshot.scope.function, snapshot.scope.context
    root = snapshot.paths[0].root.object_id
    assert root == MemoryObjectId.argument(function, 0, context)
    assert MemoryObjectId.stack(function, context, 'frame-1') != MemoryObjectId.stack(function, context, 'frame-2')
    registers = {'a0': root}
    registers['a0'] = MemoryObjectId.heap(snapshot.origin_map[0].point, context)
    assert root == MemoryObjectId.argument(function, 0, context)


def m03(snapshot):
    before, after = snapshot.reads
    assert before.state != after.state
    assert snapshot.versions[1].parents == (snapshot.versions[0].id,)
    expect_error(UnsupportedSemantics, lambda: UnimplementedMemoryQueryPort().read(after))
    module = sample_module()
    assert isinstance(module.functions[0].blocks[0].effects[0], StoreEffect)
    assert loads(dumps(snapshot)) == snapshot


def m04(snapshot):
    graph = snapshot.graphs[0]
    assert graph.summaries[0].source == graph.summaries[0].target
    assert graph.summaries[0].soundness == Completeness.UNKNOWN
    expect_error(ValueError, lambda: replace(graph, assessment=Assessment.complete()))
    expect_error(UnsupportedSemantics, lambda: UnimplementedMemoryQueryPort().resolve_alias(
        snapshot.versions[0].id, snapshot.locations[0], snapshot.locations[0]))


def m05(snapshot):
    for kind in (AliasKind.MAY, AliasKind.UNKNOWN):
        alias = AliasResult(kind, (), Assessment())
        assert select_update_policy(alias, True, True) == UpdateKind.WEAK
        expect_error(ValueError, lambda: replace(snapshot.versions[1].definition,
            update=UpdateKind.STRONG, alias=alias, unique_target=True, exact_coverage=True))
    must = AliasResult(AliasKind.MUST, ('Fixture supplies must-alias evidence',), Assessment.complete())
    assert select_update_policy(must, True, True) == UpdateKind.STRONG
    assert select_update_policy(must, True, False) == UpdateKind.WEAK
    expect_error(UnsupportedSemantics, lambda: UnimplementedMemoryQueryPort().write(snapshot.versions[1].definition))


def m06(snapshot):
    for endian in Endian:
        whole = replace(snapshot.locations[0], endian=endian)
        partial = replace(whole, offset_lower=1, offset_upper=1, width_bits=16)
        assert whole.byte_interval == (0, 4) and partial.byte_interval == (1, 3)
        assert loads(dumps(partial)).endian == endian
    assert modular_offset(-1, 32) == 0xffffffff
    _, _, _, _, _, _, _, value, _, guard = fixture()
    expect_error(ValueError, lambda: WriteRegister('o0', RegisterSlice('r0', 8, 8, 32),
        Constant(0, ValueType.bv(8)), RegisterWritePolicy.FULL, guard))


def m07(snapshot):
    effect = UnknownEffect('o0', 'Dirty', 'Unsupported side effect')
    assert effect.may_write_regions == ('*',) and effect.may_change_control
    expect_error(ValueError, lambda: UnknownEffect('o0', 'Dirty', 'unsafe omission', (), (), False))
    expect_error(ValueError, lambda: CallFootprint((), (), (), True, 'unknown'))
    definition = HavocMemory(snapshot.versions[0].id, ('*',), 'Unknown external write', 'o0')
    assert loads(dumps(definition)) == definition


def m08(snapshot):
    # Representation preservation only. No engine builds this hand-declared APG.
    path = snapshot.paths[0]
    for length in (10, 100, 1000):
        long_path = replace(path, segments=(Offset(8), Deref(32, 32, Endian.LITTLE)) * length)
        assert long_path.deref_count == length
    assert snapshot.graphs[0].summaries[0].maximum_repetitions is None
    expect_error(UnsupportedSemantics, lambda: UnimplementedMemoryQueryPort().resolve_definition(snapshot.reads[1]))


def m09(snapshot):
    budget = SemanticBudgets(apg_nodes=7, sse_nodes=13, heap_cells=23, worklist_iterations=31)
    assert len({budget.apg_nodes, budget.sse_nodes, budget.heap_cells, budget.worklist_iterations}) == 4
    assert budget.exhausted('worklist_iterations').status == Completeness.INCOMPLETE
    expect_error(ValueError, lambda: SemanticBudgets(solver_timeout_ms=0))
    expect_error(ValueError, lambda: loads(dumps(snapshot), max_nodes=5))


def m10(snapshot):
    for status in SolverStatus:
        expect_error(TypeError, lambda: bool(SolverResult(status)))
    request = LoweringRequest(snapshot, snapshot.reads[1].result)
    result = UnimplementedSolverLowering().lower(request)
    assert result.status == LoweringStatus.UNSUPPORTED and result.query is None
    expect_error(TypeError, lambda: UnimplementedSolverLowering().lower('Load(pointer,32)'))
    expect_error(ValueError, lambda: SymbolicOp('Load'))


def m11(snapshot):
    fact = snapshot.taint_facts[0]
    assert fact.graph is not None and fact.path is None and fact.guard is not None
    assert fact.memory_version == snapshot.versions[1].id and fact.provenance[-1] == 'Sink candidate'
    assert fact.assessment.precision == Precision.OVER_APPROX
    assert fact.assessment.status != Completeness.COMPLETE
    assert loads(dumps(fact)) == fact


def m12(snapshot):
    module = replace(sample_module(), memory_snapshots=(snapshot,),
        capabilities=('typed-effects', 'memory-descriptors', 'access-graph-descriptors', 'taint-fact-descriptors'))
    assert loads(dumps(module)) == module
    assert loads(dumps(snapshot)) == snapshot


CASES = {f'M-{index:02d}': function for index, function in enumerate(
    (m01, m02, m03, m04, m05, m06, m07, m08, m09, m10, m11, m12), 1)}

RUNTIME_EXPECTATIONS = {
    'M-01': 'Address addition and dereference produce distinct runtime effects',
    'M-02': 'Stable roots across register overwrite, caller/callee and frame changes',
    'M-03': 'Must-alias Store→Load reads the correct old/new memory version',
    'M-04': 'APG path-set summaries conservatively cover paths without claiming heap alias',
    'M-05': 'MayAlias weak update preserves both old and new values',
    'M-06': 'Overlapping 2-byte writes at p+1 preserve bytes/endian; byte p+1 is 0x22 LE / 0x11 BE for 0x1122',
    'M-07': 'Unknown external/IR effects conservatively havoc affected state',
    'M-08': 'Linked-list 10/100/1000, tree/doubly-linked and recursive-function runtime converges or reports Incomplete',
    'M-09': 'Independent APG/SSE/heap/worklist/alias/SMT budgets report actual counts and Incomplete',
    'M-10': 'Verified memory lowering and actual solver SAT/UNSAT/UNKNOWN/TIMEOUT remain distinct',
    'M-11': 'Source→arg.next*.data→Sink preserves guard/state/evidence without confirming a may-only vulnerability',
    'M-12': 'Python memory engine facts and diagnostics agree after serialization (Rust comparison only P10)',
}


def exercise(case):
    start = time.perf_counter()
    snapshot = snapshot_fixture()
    CASES[case](snapshot)
    return {'fixture': case, 'contract_status': 'PASS', 'runtime_gate_m': 'NOT_IMPLEMENTED',
            'expected_runtime': RUNTIME_EXPECTATIONS[case],
            'actual_runtime': 'P5 engine/coverage proof/lowering not implemented; no runtime facts returned',
            'completeness': 'incomplete', 'conservativeness': 'Representation/precondition checks only; runtime soundness unverified',
            'descriptor_counts': {'apg_nodes': 3, 'apg_edges': 2, 'apg_summaries': 1,
                'sse_nodes': 4, 'memory_versions': 2, 'object_descriptors': 1, 'taint_descriptors': 1},
            'runtime_metrics': {'apg_nodes': None, 'apg_edges': None, 'sse_nodes': None,
                'heap_objects': None, 'heap_cells': None, 'facts': None, 'worklist_steps': None,
                'solver_calls': 0, 'peak_rss': None},
            'wall_seconds': time.perf_counter() - start,
            'fallback': 'Preserved legacy VexIR/EmTaint path; no implicit memory-engine fallback'}
