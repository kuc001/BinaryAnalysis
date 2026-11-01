"""Run only inside scripts/p4_probe.py's guarded target native subprocess."""
from dataclasses import replace
import hashlib
import json
import struct
from pathlib import Path
import unittest

import archinfo
import pyvex

from emtaint.core.contracts import Constant
from emtaint.ir.canonical import (Compute, LoadEffect, StoreEffect, UnknownEffect,
    BranchEffect, ValueOp, JumpEffect, ReturnEffect, CallEffect, IndirectTarget)
from emtaint.ir.canonical.wire import dumps, loads
from emtaint.frontends.inputs import InputBlock, FunctionInput, CallHint
from emtaint.frontends.vex_lowering import NativeChunk, VEXLowerer
from emtaint.frontends.angr_vex import AngrVexFrontend
from emtaint.frontends.ida_vex import IdaVexFrontend
from test_p4_inputs import tiny_elf

WORK = None


def normalized(module):
    def visit(value):
        if type(value) is dict:
            return {key: ('paired-frontend' if key == 'frontend' and value.get('$type') == 'Producer' else visit(child))
                    for key, child in value.items()}
        if type(value) is list:
            return [visit(child) for child in value]
        return value
    return visit(json.loads(dumps(module)))


def lower_native(statements, types=(), *, arch=None, jumpkind='Ijk_Boring', next_expression=None, calls=()):
    arch = arch or archinfo.ArchX86()
    start = 0x1000
    vex = pyvex.IRSB.empty_block(arch, start,
        statements=[pyvex.stmt.IMark(start, 4, 0)] + list(statements),
        nxt=next_expression if next_expression is not None else pyvex.expr.Const(pyvex.const.U32(start + 4)),
        tyenv=pyvex.IRTypeEnv(arch, list(types)), jumpkind=jumpkind, size=4)
    spec = FunctionInput(start, 'fixture', (InputBlock(start, start + 4),), calls=calls)
    lowerer = VEXLowerer(hashlib.sha256(b'native-VEX-fixture').hexdigest(), 0, arch, 'native-fixture')
    result = lowerer.lower((spec,), (NativeChunk(spec, start, start + 4, start, start + 4,
                                    'default', vex, hashlib.sha256(b'code').hexdigest()),))
    return result, lowerer


def execute_scalar_fixture(module, memory=None):
    """Independent tiny test oracle for guarded scalar effects, not a P5 engine."""
    state, reads, stores = {}, [], []
    memory = memory or {}
    def value(operand):
        return operand.value if isinstance(operand, Constant) else state[operand.id]
    for effect in module.functions[0].blocks[0].effects:
        if isinstance(effect, Compute):
            args = [value(arg) for arg in effect.args]
            if effect.op == ValueOp.COPY:
                result = args[0]
            elif effect.op == ValueOp.ADD:
                result = args[0] + args[1]
            elif effect.op == ValueOp.IF:
                result = args[1] if args[0] else args[2]
            elif effect.op == ValueOp.EXTRACT:
                high, low = effect.params
                result = (args[0] >> low) & ((1 << (high - low + 1)) - 1)
            elif effect.op == ValueOp.ZERO_EXTEND:
                result = args[0]
            elif effect.op == ValueOp.SIGN_EXTEND:
                width = effect.args[0].type.bits
                result = args[0] - (1 << width) if args[0] & (1 << (width - 1)) else args[0]
            else:
                raise AssertionError('Oracle does not implement ' + effect.op.value)
            state[effect.result.id] = result & ((1 << effect.result.type.bits) - 1)
        elif isinstance(effect, LoadEffect) and value(effect.guard):
            address = value(effect.address)
            reads.append(address)
            raw = bytes(memory[address + i] for i in range(effect.width_bits // 8))
            state[effect.result.id] = int.from_bytes(raw, effect.endian.value)
        elif isinstance(effect, StoreEffect) and value(effect.guard):
            stores.append((value(effect.address), value(effect.value), effect.endian.value, effect.width_bits))
    return state, reads, stores


class NativeCases(unittest.TestCase):
    def paired(self, code):
        path = WORK / ('fixture-' + hashlib.sha256(code).hexdigest()[:12] + '.elf')
        if not path.exists():
            path.write_bytes(tiny_elf(code))
        spec = FunctionInput(0x400100, 'fixture', (InputBlock(0x400100, 0x400100 + len(code)),))
        a = AngrVexFrontend(path).lift((spec,))
        b = IdaVexFrontend(path).lift((spec,))
        self.assertEqual(normalized(a.module), normalized(b.module))
        self.assertEqual(a.mappings, b.mappings)
        self.assertEqual(a.cfgs(), b.cfgs())
        return a, b

    def test_real_bytes_two_frontends_load_store_roundtrip(self):
        result, _ = self.paired(bytes.fromhex('488b074883c001488907c3'))
        effects = [effect for block in result.module.functions[0].blocks for effect in block.effects]
        self.assertTrue(any(isinstance(e, LoadEffect) for e in effects))
        self.assertTrue(any(isinstance(e, StoreEffect) for e in effects))
        self.assertEqual(loads(dumps(result.module)), result.module)
        self.assertEqual(sum(result.report()['statement_status_counts'].values()),
                         sum(result.report()['source_statement_histogram'].values()))

    def test_one_source_block_lifts_into_multiple_irsbs(self):
        result, _ = self.paired(bytes.fromhex('90eb0090c3'))
        self.assertGreaterEqual(len(result.mappings), 2)
        self.assertEqual({r['source_start'] for r in result.mappings}, {0x400100})

    def test_native_side_exit_splits_continuation_before_later_store(self):
        result, _ = lower_native((
            pyvex.stmt.Exit(pyvex.expr.Const(pyvex.const.U1(1)), pyvex.const.U32(0x1004), 'Ijk_Boring', 68),
            pyvex.stmt.WrTmp(0, pyvex.expr.Const(pyvex.const.U32(7))),
            pyvex.stmt.Store(pyvex.expr.Const(pyvex.const.U32(0x5000)), pyvex.expr.RdTmp(0), 'Iend_LE'),), ('Ity_I32',))
        blocks = result.module.functions[0].blocks
        self.assertIsInstance(blocks[0].effects[-1], BranchEffect)
        self.assertFalse(any(isinstance(e, StoreEffect) for e in blocks[0].effects))
        self.assertTrue(any(isinstance(e, StoreEffect) for e in blocks[1].effects))

    def test_guarded_load_false_keeps_alternate_and_performs_no_read(self):
        for sign in ('U', 'S'):
            for guard in (0, 1):
                stmt = pyvex.stmt.LoadG('Iend_LE', 'ILGop_8' + sign + 'to32', 0,
                    pyvex.expr.Const(pyvex.const.U32(0x5000)), pyvex.expr.Const(pyvex.const.U32(0x1234)),
                    pyvex.expr.Const(pyvex.const.U1(guard)))
                result, lowerer = lower_native((stmt,), ('Ity_I32',))
                state, reads, _ = execute_scalar_fixture(result.module, {0x5000: 0x80})
                expected = (0x80 if sign == 'U' else 0xffffff80) if guard else 0x1234
                self.assertEqual(state[lowerer.tmps[0].id], expected)
                self.assertEqual(reads, [0x5000] if guard else [])

    def test_guarded_store_and_endianness_are_preserved(self):
        for guard in (0, 1):
            stmt = pyvex.stmt.StoreG('Iend_BE', pyvex.expr.Const(pyvex.const.U32(0x5000)),
                pyvex.expr.Const(pyvex.const.U16(0x1234)), pyvex.expr.Const(pyvex.const.U1(guard)))
            result, _ = lower_native((stmt,))
            _, _, stores = execute_scalar_fixture(result.module)
            self.assertEqual(stores, [(0x5000, 0x1234, 'big', 16)] if guard else [])

    def test_cas_llsc_dirty_barrier_are_explicit_conservative_unknowns(self):
        c = lambda n: pyvex.expr.Const(pyvex.const.U32(n))
        statements = (
            pyvex.stmt.CAS(c(0x5000), c(7), None, c(6), None, 0, 0xffffffff, 'Iend_LE'),
            pyvex.stmt.LLSC(c(0x5000), None, 1, 'Iend_LE'),
            pyvex.stmt.Dirty(pyvex.enums.IRCallee(0, 'opaque_helper', 0),
                pyvex.expr.Const(pyvex.const.U1(1)), (), 2, 'Ifx_Modify', c(0x5000), 4, 0),
            pyvex.stmt.MBE('Imbe_Fence'))
        result, _ = lower_native(statements, ('Ity_I32',) * 3)
        effects = [e for b in result.module.functions[0].blocks for e in b.effects if isinstance(e, UnknownEffect)]
        self.assertEqual(len(effects), 4)
        for effect in effects:
            self.assertEqual(effect.may_write_regions, ('*',))
            self.assertEqual(effect.may_write_registers, ('*',))

    def test_unknown_tmp_is_not_replaced_by_zero_or_used_in_a_known_store(self):
        c = lambda n: pyvex.expr.Const(pyvex.const.U32(n))
        result, _ = lower_native((pyvex.stmt.WrTmp(0, pyvex.expr.Binop('Iop_DivU32', [c(1),c(2)])),
            pyvex.stmt.Store(c(0x5000), pyvex.expr.RdTmp(0), 'Iend_LE')), ('Ity_I32',))
        effects = [e for b in result.module.functions[0].blocks for e in b.effects]
        self.assertFalse(any(isinstance(e, StoreEffect) for e in effects))
        self.assertIn('UndefinedTmp', result.module.assessment.unsupported_ops)

    def test_decode_failure_is_explicit_and_bounded(self):
        result, _ = self.paired(bytes.fromhex('0f'))
        self.assertIn('LiftFailure', result.module.assessment.unsupported_ops)

    def test_cfgfast_selection_is_available_without_ida_bounds(self):
        path = WORK / 'discovery.elf'
        path.write_bytes(tiny_elf(bytes.fromhex('90c3')))
        frontend = AngrVexFrontend(path)
        specs = frontend.discover((0x400100,))
        self.assertEqual(specs[0].address, 0x400100)
        self.assertTrue(frontend.lift(specs).module.functions)

    def test_thumb_mode_and_imark_delta_survive_both_frontends(self):
        code = bytes.fromhex('086810607047')  # ldr r0,[r1]; str r0,[r2]; bx lr
        data = bytearray(0x100 + len(code))
        data[:16] = b'\x7fELF\x01\x01\x01' + b'\0' * 9
        struct.pack_into('<HHIIIIIHHHHHH', data, 16, 2, 40, 1, 0x8101, 52, 0, 0x5000000,
                         52, 32, 1, 0, 0, 0)
        struct.pack_into('<IIIIIIII', data, 52, 1, 0, 0x8000, 0, len(data), len(data), 5, 0x1000)
        data[0x100:] = code
        path = WORK / 'thumb.elf'
        path.write_bytes(data)
        specs = (FunctionInput(0x8100, 'thumb', (InputBlock(0x8100, 0x8106, 'thumb'),)),)
        a, b = AngrVexFrontend(path).lift(specs), IdaVexFrontend(path).lift(specs)
        self.assertEqual(normalized(a.module), normalized(b.module))
        self.assertTrue(all(block.id.mode == 'thumb' for f in a.module.functions for block in f.blocks))
        self.assertTrue(any(row['imark_delta'] == 1 for row in a.coverage))

    def test_call_name_hint_does_not_turn_an_indirect_call_into_external_proof(self):
        result, _ = lower_native((pyvex.stmt.WrTmp(0, pyvex.expr.Get(8, 'Ity_I32')),),
            ('Ity_I32',), arch=archinfo.ArchARMEL(), jumpkind='Ijk_Call', next_expression=pyvex.expr.RdTmp(0),
            calls=(CallHint(0x1000, 0x1000, 'iCall'),))
        calls = [e for b in result.module.functions[0].blocks for e in b.effects if isinstance(e, CallEffect)]
        self.assertIsInstance(calls[0].target, IndirectTarget)
        self.assertEqual(calls[0].footprint.write_regions, ('*',))
        self.assertIn('r0', calls[0].footprint.clobbered_registers)
        self.assertNotIn('r4', calls[0].footprint.clobbered_registers)

    def test_constant_temporary_call_has_scalar_proof_independent_of_name_hint(self):
        from emtaint.ir.canonical import DirectTarget
        result, _ = lower_native((pyvex.stmt.WrTmp(0, pyvex.expr.Const(pyvex.const.U32(0x2000))),),
            ('Ity_I32',), jumpkind='Ijk_Call', next_expression=pyvex.expr.RdTmp(0),
            calls=(CallHint(0x1000, 0x1000, 'iCall'),))
        call=next(e for b in result.module.functions[0].blocks for e in b.effects if isinstance(e,CallEffect))
        self.assertIsInstance(call.target,DirectTarget)
        self.assertEqual(call.target.function.rva,0x2000)

    def test_store_conditional_is_not_a_normal_store(self):
        result, _ = lower_native((pyvex.stmt.LLSC(pyvex.expr.Const(pyvex.const.U32(0x5000)),
            pyvex.expr.Const(pyvex.const.U32(7)), 0, 'Iend_LE'),), ('Ity_I1',))
        effects = [e for b in result.module.functions[0].blocks for e in b.effects]
        self.assertFalse(any(isinstance(e, StoreEffect) for e in effects))
        self.assertIn('Ist_LLSC', result.module.assessment.unsupported_ops)

    def test_boolean_vex_operations_remain_boolean_cir(self):
        for opcode in ('Iop_And1', 'Iop_Or1', 'Iop_Xor1'):
            result, _ = lower_native((pyvex.stmt.WrTmp(0, pyvex.expr.Binop(opcode,
                [pyvex.expr.Const(pyvex.const.U1(1)), pyvex.expr.Const(pyvex.const.U1(0))])),), ('Ity_I1',))
            self.assertNotIn(opcode, result.module.assessment.unsupported_ops)
            self.assertEqual(loads(dumps(result.module)), result.module)

    def test_unknown_side_exit_keeps_its_known_target_in_cfg(self):
        from emtaint.graph import FlowKind
        result, _ = lower_native((pyvex.stmt.Exit(pyvex.expr.RdTmp(0), pyvex.const.U32(0x1004),
            'Ijk_Boring', 68),), ('Ity_I1',))
        self.assertTrue(any(edge.kind == FlowKind.UNKNOWN for graph in result.cfgs() for edge in graph.edges))
