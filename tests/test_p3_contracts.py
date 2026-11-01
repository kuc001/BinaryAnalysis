"""P3 typed representation contracts, deliberately not P5 heap execution tests."""
from dataclasses import replace
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from emtaint.core.contracts import (Assessment, Precision, UnsupportedSemantics,
    ValueType, TypeKind, Constant, ValueRef, Producer, Origin, AnalysisScope,
    SymbolicExprId, MemoryVersionId, AccessPathId, AccessGraphId, MemoryLocationId)
from emtaint.core import (BinaryId, FunctionId, BlockId, ProgramPoint, ContextId,
                          MemoryObjectId, Architecture, ABI, Endian, MemoryObject)
from emtaint.ir.canonical import (Compute, ValueOp, LoadEffect, StoreEffect, CIRBlock,
    CIRFunction, CIRModule, UnknownEffect, HavocEffect, RegisterSlice, WriteRegister,
    RegisterWritePolicy, CallEffect, ExternalTarget, CallFootprint, BranchEffect)
from emtaint.memory import (AccessRoot, Offset, Deref, Index, UnknownOffset, AccessPath,
    APGNode, APGEdge, APGSummary, AccessGraph, MemoryLocation, AliasKind, AliasResult,
    UpdateKind, select_update_policy, InitialMemory, WriteMemory, JoinInput, JoinMemory,
    MemoryVersion, ReadMemory, SymbolicNode, SymbolicOp, MemorySnapshot)
from emtaint.memory.query_port import UnimplementedMemoryQueryPort
from emtaint.solver.lowering import UnimplementedSolverLowering, LoweringRequest, LoweringStatus
from emtaint.ir.canonical.wire import dumps, loads, schema_documents


def fixture():
    binary = BinaryId.from_bytes(b'P3 contract fixture')
    fid = FunctionId(binary, 0)
    block = BlockId(fid, 0)
    point = ProgramPoint(block, 0, 0)
    producer = Producer('P3 fixture', '1', 'fixture')
    origin = Origin('o0', point, producer, 'fixture')
    scope = AnalysisScope(fid, ContextId(), 'fixture-session', 0, 0)
    arch = Architecture('fixture32', 32, 32, Endian.LITTLE)
    root = AccessRoot(MemoryObjectId.argument(fid, 0, ContextId()), 'argument', 'default', 'o0')
    value = ValueRef('value', ValueType.bv(32))
    address = ValueRef('address', ValueType.pointer(32))
    truth = Constant(True, ValueType.boolean())
    return binary, fid, block, origin, scope, arch, root, value, address, truth


def sample_module():
    binary, fid, bid, origin, _, arch, _, value, address, truth = fixture()
    effects = (StoreEffect('o0', address, value, 32, Endian.LITTLE, truth),
               LoadEffect('o0', value, address, 32, Endian.LITTLE, truth))
    function = CIRFunction(fid, (value, address), (CIRBlock(bid, effects),), bid, ABI('fixture'))
    return CIRModule(origin.producer, arch, arch.endian, binary.sha256, (function,),
                     (origin,), ('typed-effects',), Assessment())


class CIRTests(unittest.TestCase):
    def test_load_store_are_ordered_effects_with_width_endian_guard_origin(self):
        module = sample_module()
        effects = module.functions[0].blocks[0].effects
        self.assertIsInstance(effects[0], StoreEffect)
        self.assertIsInstance(effects[1], LoadEffect)
        self.assertEqual((effects[0].width_bits, effects[0].endian, effects[0].origin), (32, Endian.LITTLE, 'o0'))
        self.assertEqual(loads(dumps(module)), module)

    def test_width_guard_address_and_constant_sort_validation(self):
        _, _, _, _, _, _, _, value, address, truth = fixture()
        for build in (lambda: StoreEffect('o0', address, value, 16, Endian.BIG, truth),
                      lambda: LoadEffect('o0', value, value, 32, Endian.LITTLE, truth),
                      lambda: LoadEffect('o0', value, address, 32, Endian.LITTLE, value),
                      lambda: Constant(256, ValueType.bv(8)),
                      lambda: Constant(True, ValueType.bv(8))):
            with self.subTest(build=build), self.assertRaises((ValueError, TypeError)):
                build()

    def test_computation_is_typed_and_memory_is_not_a_value_op(self):
        _, _, _, _, _, _, _, value, _, _ = fixture()
        Compute('o0', value, ValueOp.ADD, (value, Constant(8, ValueType.bv(32))))
        with self.assertRaises(ValueError):
            Compute('o0', value, ValueOp.ADD, (value, Constant(8, ValueType.bv(16))))
        with self.assertRaises(ValueError):
            ValueOp('Load')

    def test_origin_scope_and_unsupported_effects_cannot_be_silently_dropped(self):
        module = sample_module()
        block = module.functions[0].blocks[0]
        unknown = UnknownEffect('o0', 'Dirty', 'unknown external effect')
        function = replace(module.functions[0], blocks=(replace(block, effects=(unknown,)),))
        with self.assertRaises(ValueError):
            replace(module, functions=(function,))
        safe = replace(module, functions=(function,), assessment=Assessment(
            precision=Precision.INCOMPLETE, unsupported_ops=('Dirty',), diagnostics=('unmodeled effect',)))
        self.assertEqual(loads(dumps(safe)), safe)
        with self.assertRaises(ValueError):
            replace(module, origin_map=())

    def test_register_policy_call_footprint_and_control_targets(self):
        from emtaint.core import CallSiteId, Register
        module = sample_module()
        f, block = module.functions[0], module.functions[0].blocks[0]
        guard = Constant(True, ValueType.boolean())
        small = Constant(0x80, ValueType.bv(8))
        write = WriteRegister('o0', RegisterSlice('r0', 0, 8, 32), small,
                              RegisterWritePolicy.ZERO_UPPER, guard)
        arch = replace(module.architecture, registers=(Register('r0', 32),))
        registered = replace(module, architecture=arch,
            functions=(replace(f, blocks=(replace(block, effects=(write,)),)),))
        self.assertEqual(loads(dumps(registered)), registered)
        with self.assertRaises(ValueError):
            replace(module, functions=registered.functions)
        call = CallEffect('o0', CallSiteId(module.origin_map[0].point), ExternalTarget('unknown_external'),
                           (), (), ABI('fixture'), guard)
        called = replace(f, blocks=(replace(block, effects=(call,)),))
        with self.assertRaises(ValueError):
            replace(module, functions=(called,))
        assessed = replace(module, functions=(called,), assessment=Assessment(unsupported_ops=('CallMemoryEffects',)))
        self.assertEqual(loads(dumps(assessed)), assessed)
        with self.assertRaises(ValueError):
            replace(block, effects=(BranchEffect('o0', guard, block.id, block.id), write))

    def test_pointer_declarations_and_missing_capabilities_fail_closed(self):
        module = sample_module()
        f = module.functions[0]
        bad = replace(f, values=f.values + (ValueRef('unused-bad-pointer', ValueType.pointer(64)),))
        with self.assertRaises(ValueError):
            replace(module, functions=(bad,))
        with self.assertRaises(ValueError):
            replace(module, capabilities=())
        high = FunctionId(f.function_id.binary, 1 << 32)
        with self.assertRaises(ValueError):
            replace(module, functions=(CIRFunction(high, (), (), None, f.abi),), origin_map=())

    def test_unreferenced_origin_must_still_name_a_declared_block(self):
        module = sample_module()
        origin = module.origin_map[0]
        bad = replace(origin, id='dangling-source', point=ProgramPoint(BlockId(origin.point.function, 99), 0, 99))
        with self.assertRaises(ValueError):
            replace(module, origin_map=module.origin_map + (bad,))


class MemorySnapshotTests(unittest.TestCase):
    def snapshot(self):
        from conformance.memory.fixtures import snapshot_fixture
        return snapshot_fixture()

    def test_cross_revision_and_dangling_references_are_rejected(self):
        snapshot = self.snapshot()
        scope = replace(snapshot.scope, cg_version=1)
        with self.assertRaises(ValueError):
            replace(snapshot, scope=scope)
        with self.assertRaises(ValueError):
            replace(snapshot, versions=snapshot.versions[:1])
        with self.assertRaises(ValueError):
            replace(snapshot, objects=())
        with self.assertRaises(ValueError):
            replace(snapshot, paths=snapshot.paths * 2)

    def test_combined_sse_memory_definition_cycle_is_rejected(self):
        snapshot = self.snapshot()
        written = snapshot.versions[1]
        cyclic = replace(written, definition=replace(written.definition, value=snapshot.reads[1].result))
        with self.assertRaises(ValueError):
            replace(snapshot, versions=(snapshot.versions[0], cyclic))

    def test_taint_graph_root_and_object_address_spaces_are_checked(self):
        snapshot = self.snapshot()
        root = snapshot.paths[0].root
        other_id = MemoryObjectId.argument(snapshot.scope.function, 1, snapshot.scope.context)
        other_root = replace(root, object_id=other_id)
        with self.assertRaises(ValueError):
            replace(snapshot, objects=snapshot.objects + (MemoryObject(other_id, 'second root'),),
                    taint_facts=(replace(snapshot.taint_facts[0], root=other_root),))
        with self.assertRaises(ValueError):
            replace(snapshot, locations=(replace(snapshot.locations[0], address_space='io'),))

    def test_unimplemented_ports_raise_instead_of_returning_empty_results(self):
        snapshot = self.snapshot()
        port = UnimplementedMemoryQueryPort()
        for operation in (lambda: port.read(snapshot.reads[0]),
                          lambda: port.write(snapshot.versions[1].definition),
                          lambda: port.resolve_definition(snapshot.reads[0]),
                          lambda: port.points_to(snapshot.versions[0].id, snapshot.expressions[0].id),
                          lambda: port.resolve_alias(snapshot.versions[0].id, snapshot.locations[0], snapshot.locations[0])):
            with self.subTest(operation=operation), self.assertRaises(UnsupportedSemantics):
                operation()

    def test_scope_factory_rejects_stale_session_graph_references(self):
        from test_program_models import fixture as program_fixture
        from emtaint.core import AnalysisSession
        from emtaint.graph import FlowEdge
        program, fid, _, a, b, *_ = program_fixture()
        session = AnalysisSession(program)
        scope = AnalysisScope.from_session(session, fid, ContextId())
        scope.assert_current(session)
        with self.assertRaises(ValueError):
            scope.assert_current(AnalysisSession(program))
        session.replace_cfg(session.cfg(fid).with_edge(FlowEdge(a, b)))
        with self.assertRaises(ValueError):
            scope.assert_current(session)

    def test_strong_write_requires_singleton_object_evidence(self):
        from emtaint.memory import HeapObject, ObjectCardinality, ObjectLifetime
        snapshot = self.snapshot()
        must = AliasResult(AliasKind.MUST, ('fixture must-alias evidence',), Assessment.complete())
        write = replace(snapshot.versions[1].definition, update=UpdateKind.STRONG, alias=must,
                         unique_target=True, exact_coverage=True)
        versions = (snapshot.versions[0], replace(snapshot.versions[1], definition=write))
        with self.assertRaises(ValueError):
            replace(snapshot, versions=versions)
        object_fact = HeapObject(snapshot.objects[0].id, 'argument', ObjectCardinality.SINGLETON,
                                  ObjectLifetime.EXTERNAL, None, ('Fixture declares singleton',))
        valid = replace(snapshot, versions=versions, object_facts=(object_fact,))
        self.assertEqual(loads(dumps(valid)), valid)
        with self.assertRaises(ValueError):
            replace(valid, object_facts=(replace(object_fact, cardinality=ObjectCardinality.SUMMARY),))

    def test_sse_scalar_operations_are_typed_with_shared_id_operands(self):
        snapshot = self.snapshot()
        x, truth = snapshot.expressions[0], snapshot.expressions[1]
        extra = (
            SymbolicNode(SymbolicExprId(snapshot.scope, 'multiply'), x.type, SymbolicOp.MUL, (x.id, x.id), 'o0'),
            SymbolicNode(SymbolicExprId(snapshot.scope, 'low8'), ValueType.bv(8), SymbolicOp.EXTRACT,
                         (x.id,), 'o0', params=(7, 0)),
            SymbolicNode(SymbolicExprId(snapshot.scope, 'ite'), x.type, SymbolicOp.IF, (truth.id, x.id, x.id), 'o0'),
        )
        typed = replace(snapshot, expressions=snapshot.expressions + extra)
        self.assertEqual(loads(dumps(typed)), typed)
        with self.assertRaises(ValueError):
            replace(snapshot, expressions=snapshot.expressions + (replace(extra[1], params=(40, 33)),))

    def test_lowering_query_operation_and_limit_are_explicit(self):
        snapshot = self.snapshot()
        value = snapshot.reads[0].result
        boolean_id = snapshot.expressions[1].id
        LoweringRequest(snapshot, value, operation='eval', limit=2)
        LoweringRequest(snapshot, boolean_id, operation='check')
        with self.assertRaises(ValueError):
            LoweringRequest(snapshot, value, operation='check')
        with self.assertRaises(ValueError):
            LoweringRequest(snapshot, boolean_id, operation='min')
        with self.assertRaises(ValueError):
            LoweringRequest(snapshot, value, limit=0)


class AccessContractTests(unittest.TestCase):
    def test_offset_and_dereference_are_distinct(self):
        _, _, _, _, scope, _, root, _, _, _ = fixture()
        base = AccessPath(AccessPathId(scope, 'address'), root, (Offset(8),), 32, Endian.LITTLE, 'o0')
        read = replace(base, id=AccessPathId(scope, 'read'), segments=(Offset(8), Deref(32, 32, Endian.LITTLE)))
        self.assertEqual((base.deref_count, read.deref_count), (0, 1))
        self.assertNotEqual(base, read)

    def test_unknown_offsets_and_indices_remain_explicit(self):
        _, _, _, _, scope, _, root, _, _, _ = fixture()
        path = AccessPath(AccessPathId(scope, 'indexed'), root,
            (Index(SymbolicExprId(scope, 'index'), 4, 0, 7), UnknownOffset(None, None, 'top offset')),
            8, Endian.BIG, 'o0')
        self.assertEqual(loads(dumps(path)), path)
        with self.assertRaises(ValueError):
            UnknownOffset(7, 3, 'invalid')

    def test_strong_update_requires_must_alias_and_unique_exact_coverage(self):
        unknown = AliasResult(AliasKind.UNKNOWN, (), Assessment())
        self.assertEqual(select_update_policy(unknown, True, True), UpdateKind.WEAK)
        with self.assertRaises(ValueError):
            AliasResult(AliasKind.MUST, (), Assessment())
        exact = Assessment.complete()
        must = AliasResult(AliasKind.MUST, ('fixture proof',), exact)
        self.assertEqual(select_update_policy(must, True, True), UpdateKind.STRONG)
        self.assertEqual(select_update_policy(must, False, True), UpdateKind.WEAK)
        with self.assertRaises(TypeError):
            bool(unknown)


class WireTests(unittest.TestCase):
    def test_versions_fields_and_native_types_fail_closed(self):
        module = sample_module()
        encoded = json.loads(dumps(module))
        for key, value in (('schema_version', 'CIR-Wire-v999'), ('unexpected', True)):
            bad = dict(encoded, **{key: value})
            with self.subTest(key=key), self.assertRaises((ValueError, TypeError)):
                loads(json.dumps(bad))
        with self.assertRaises(TypeError):
            dumps(object())

    def test_duplicate_keys_and_decode_budget_reject_input(self):
        with self.assertRaises(ValueError):
            loads('{"x":1,"x":2}')
        with self.assertRaises(ValueError):
            loads(dumps(sample_module()), max_nodes=3)
        with self.assertRaises(ValueError):
            loads(dumps(sample_module()), max_bytes=10)

    def test_fragment_extra_fields_unknown_enums_and_huge_integers(self):
        encoded = json.loads(dumps(sample_module()))
        encoded['architecture']['extra'] = 'must not be dropped'
        with self.assertRaises(ValueError):
            loads(json.dumps(encoded))
        encoded = json.loads(dumps(sample_module()))
        encoded['endian']['value'] = 'middle'
        with self.assertRaises(ValueError):
            loads(json.dumps(encoded))
        with self.assertRaises(ValueError):
            dumps(Offset(1 << 5000))
        with self.assertRaises(ValueError):
            loads(dumps(sample_module()), max_depth=2)

    def test_schemas_match_the_frozen_generated_documents(self):
        for name, schema in schema_documents().items():
            path = ROOT / 'docs/migration/schemas' / name
            self.assertEqual(json.loads(path.read_text(encoding='utf8')), schema)

    def test_published_schema_shape_accepts_fixture_and_rejects_extra_keys(self):
        from schema_shape import validate_shape
        schema = schema_documents()['cir-wire-v1.json']
        document = json.loads(dumps(sample_module()))
        validate_shape(document, schema)
        document['functions'][0]['bogus'] = 'not portable'
        with self.assertRaises(ValueError):
            validate_shape(document, schema)

    def test_native_import_blocker_in_clean_python(self):
        code = '''
import importlib.abc,sys
class Deny(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname.split('.')[0] in {'angr','pyvex','claripy','idaapi','ida_hexrays','networkx'}:
   raise RuntimeError(fullname)
sys.meta_path.insert(0,Deny())
import emtaint.ir.canonical,emtaint.memory,emtaint.solver.lowering
print('PASS')
'''
        result = subprocess.run([sys.executable, '-B', '-S', '-c', code], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main()
