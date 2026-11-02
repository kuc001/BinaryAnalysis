"""Shared native VEX→CIR boundary. Unsupported semantics remain conservative."""
from collections import Counter
from dataclasses import dataclass, replace
import importlib.metadata
import re

import pyvex

from emtaint.core import (ABI, Architecture, Register, BinaryId, FunctionId, BlockId,
    ProgramPoint, CallSiteId, Completeness, Endian)
from emtaint.core.contracts import (Assessment, Precision, Producer, Origin, ValueType,
    ValueRef, Constant, TypeKind)
from emtaint.ir.canonical import (Compute, ValueOp, LoadEffect, StoreEffect, RegisterSlice,
    RegisterWritePolicy, ReadRegister, WriteRegister, CallEffect, CallFootprint,
    DirectTarget, IndirectTarget, ExternalTarget, BranchEffect, JumpEffect, ReturnEffect,
    UnknownEffect, CIRBlock, CIRFunction, CIRModule)
from .inputs import FunctionInput, InputError
from .arm_scalar import ARMScalarLowering


class UnsupportedVEX(ValueError):
    def __init__(self, opcode, detail):
        self.opcode, self.detail = opcode, detail
        super().__init__(opcode + ': ' + detail)


@dataclass
class NativeChunk:
    function: FunctionInput
    source_start: int
    source_end: int
    start: int
    end: int
    mode: str
    vex: object | None
    byte_sha256: str
    failure: str = ''


@dataclass(frozen=True)
class FrontendResult:
    module: CIRModule
    coverage: tuple[dict, ...]
    mappings: tuple[dict, ...]
    metadata: dict

    def cfgs(self):
        from emtaint.graph import ControlFlowGraph, FlowEdge, FlowKind
        origins = {o.id: o for o in self.module.origin_map}
        result = []
        for function in self.module.functions:
            edges, exits = set(), set()
            by_address = {}
            for block in function.blocks:
                by_address.setdefault(block.id.rva + self.metadata['image_base'], block.id)
                for effect in block.effects:
                    if isinstance(effect, BranchEffect):
                        edges.add(FlowEdge(block.id, effect.if_true, FlowKind.TRUE))
                        edges.add(FlowEdge(block.id, effect.if_false, FlowKind.FALSE))
                    elif isinstance(effect, JumpEffect) and isinstance(effect.target, BlockId):
                        edges.add(FlowEdge(block.id, effect.target, FlowKind.JUMP))
                    elif isinstance(effect, ReturnEffect):
                        exits.add(block.id)
            translated_branches = {effect.origin for block in function.blocks for effect in block.effects
                                   if isinstance(effect, BranchEffect)}
            for row in self.metadata.get('native_control_flow', ()):
                if row['function'] != function.function_id.rva + self.metadata['image_base']:
                    continue
                if 'guard_class' in row and row['origin'] not in translated_branches and row['kind'] == 'Ijk_Boring':
                    target = row['target'] & ~1 if origins[row['origin']].point.block.mode == 'thumb' else row['target']
                    if target in by_address:
                        edges.add(FlowEdge(origins[row['origin']].point.block, by_address[target], FlowKind.UNKNOWN,
                                          'Native side-exit target preserved; guard lowering is incomplete'))
            result.append(ControlFlowGraph(function.function_id, frozenset(b.id for b in function.blocks),
                frozenset(edges), function.entry, frozenset(exits), Completeness.INCOMPLETE,
                'Bounded lifting; unknown guards, computed targets and external boundaries remain explicit'))
        return tuple(result)

    def report(self):
        statements = Counter(row['source_opcode'] for row in self.coverage if row['kind'] == 'statement')
        statuses = Counter(row['status'] for row in self.coverage if row['kind'] == 'statement')
        cfgs = [{'function_rva': g.function.rva, 'nodes': sorted(n.token for n in g.nodes),
                 'edges': sorted((e.source.token, e.target.token, e.kind.value, e.label) for e in g.edges),
                 'status': g.status.value} for g in self.cfgs()]
        return {'producer': self.module.producer.frontend, 'binary_sha256': self.module.binary_sha256,
                'functions': len(self.module.functions), 'cir_blocks': sum(len(f.blocks) for f in self.module.functions),
                'source_statement_histogram': dict(statements), 'statement_status_counts': dict(statuses),
                'coverage': list(self.coverage), 'block_mappings': list(self.mappings),
                'unsupported_ops': list(self.module.assessment.unsupported_ops),
                'status': self.module.assessment.status.value, 'metadata': self.metadata, 'cfgs': cfgs}


def architecture_descriptor(native):
    registers = tuple(Register(r.name, r.size * 8, r.vex_offset) for r in native.register_list
                      if r.vex_offset is not None and r.size > 0)
    return Architecture(native.name, native.bits, native.bits,
        Endian.LITTLE if native.memory_endness == 'Iend_LE' else Endian.BIG, registers=registers)


class VEXLowerer(ARMScalarLowering):
    def __init__(self, binary_sha, image_base, native_arch, frontend):
        self.binary = BinaryId(binary_sha)
        self.base, self.native_arch = image_base, native_arch
        self.arch = architecture_descriptor(native_arch)
        self.producer = Producer('BinaryAnalysis VEX frontend',
            'angr=' + importlib.metadata.version('angr') + '/pyvex=' + importlib.metadata.version('pyvex'), frontend)
        self.abi = ABI('unmodeled:' + native_arch.name)
        if native_arch.name == 'ARMEL':
            self.abi = ABI('AAPCS32:ELF', ('r0', 'r1', 'r2', 'r3'), ('r0',), 'sp', 8,
                ('r0', 'r1', 'r2', 'r3', 'r12', 'lr', 'cc_op', 'cc_dep1', 'cc_dep2', 'cc_ndep'),
                ('r4', 'r5', 'r6', 'r7', 'r8', 'r9', 'r10', 'r11', 'sp'))
        self.origins, self.coverage, self.mappings = [], [], []
        self.unsupported = set()
        self.expression_histogram = Counter()
        self.native_control = []

    def count_expressions(self, statement):
        pending = []
        for name in ('data', 'addr', 'guard', 'alt', 'storedata', 'dataLo', 'dataHi', 'expdLo', 'expdHi', 'mAddr', 'ix'):
            candidate = getattr(statement, name, None)
            if isinstance(candidate, pyvex.expr.IRExpr):
                pending.append(candidate)
        pending.extend(a for a in getattr(statement, 'args', ()) if isinstance(a, pyvex.expr.IRExpr))
        visits = 0
        while pending:
            expression = pending.pop()
            visits += 1
            if visits > 10000:
                raise UnsupportedVEX('ExpressionBudget', 'Source expression traversal budget exceeded')
            self.expression_histogram[getattr(expression, 'op', expression.tag)] += 1
            pending.extend(getattr(expression, 'args', ()))
            if isinstance(expression, pyvex.expr.ITE):
                pending.extend((expression.cond, expression.iftrue, expression.iffalse))
            if isinstance(expression, pyvex.expr.Load):
                pending.append(expression.addr)

    def rva(self, addr):
        if not self.base <= addr < 1 << self.arch.address_bits:
            raise InputError('Address is outside the declared image mapping')
        return addr - self.base

    def ref(self, type_, prefix='v'):
        result = ValueRef(f'f{self.fid.rva:x}:{prefix}{len(self.values)}', type_)
        self.values.append(result)
        return result

    def compute(self, op, args, type_, params=()):
        result = self.ref(type_)
        self.effects.append(Compute(self.origin.id, result, op, tuple(args), tuple(params)))
        known=[self.known_constant(a) for a in args]
        if all(a is not None for a in known):
            a=[x.value for x in known]
            value=None
            if op==ValueOp.COPY:value=a[0]
            elif op==ValueOp.OR:value=a[0]|a[1]
            elif op==ValueOp.AND:value=a[0]&a[1]
            elif op==ValueOp.XOR:value=a[0]^a[1]
            elif op==ValueOp.ADD:value=a[0]+a[1]
            elif op==ValueOp.SUB:value=a[0]-a[1]
            if value is not None:self.constant_values[result.id]=Constant(bool(value) if type_.kind==TypeKind.BOOL else value%(1<<type_.bits), type_)
        return result

    def known_constant(self, operand):
        return operand if isinstance(operand, Constant) else self.constant_values.get(operand.id)

    def ptr(self, value):
        if value.type.kind == TypeKind.POINTER:
            return value
        if value.type.kind != TypeKind.BV or value.type.bits != self.arch.pointer_bits:
            raise UnsupportedVEX('AddressSort', 'Address needs a full-width bitvector')
        # V1 has no implicit BV→pointer cast: materialize its numeric address
        # as 0(pointer) + BV, preserving the exact bit pattern modulo width.
        return self.compute(ValueOp.ADD, (Constant(0, ValueType.pointer(self.arch.pointer_bits)), value),
                            ValueType.pointer(self.arch.pointer_bits))

    def new_block_id(self, addr, mode):
        rva = self.rva(addr)
        index = self.variants[rva]
        self.variants[rva] += 1
        return BlockId(self.fid, rva, index=index, mode=mode)

    def set_origin(self, opcode, index):
        identifier = f'f{self.fid.rva:x}:o{len(self.origins)}'
        self.origin = Origin(identifier, ProgramPoint(self.current_id, index, self.rva(self.instruction)),
                             self.producer, opcode)
        self.origins.append(self.origin)

    def register_slice(self, offset, width):
        choices = [r for r in self.arch.registers if r.offset <= offset
                   and (offset - r.offset) * 8 + width <= r.bits]
        if not choices:
            raise UnsupportedVEX('RegisterSlice', f'Unmapped guest register {offset}:{width}')
        register = sorted(choices, key=lambda r: (-r.bits, r.offset, r.name))[0]
        return RegisterSlice(register.name, (offset - register.offset) * 8, width, register.bits)

    def type_of(self, expression):
        type_ = expression.result_type(self.vex.tyenv)
        if not re.fullmatch(r'Ity_I\d+', type_):
            raise UnsupportedVEX(type_, 'Float/vector/invalid expression type is not modeled')
        width = int(type_[5:])
        return ValueType.boolean() if width == 1 else ValueType.bv(width)

    def expr(self, expression):
        if isinstance(expression, pyvex.expr.RdTmp):
            if expression.tmp not in self.tmps:
                raise UnsupportedVEX('UndefinedTmp', 'Temporary was undefined or produced by an unsupported statement')
            return self.tmps[expression.tmp]
        type_ = self.type_of(expression)
        if isinstance(expression, pyvex.expr.Const):
            return Constant(bool(expression.con.value) if type_.kind == TypeKind.BOOL else expression.con.value, type_)
        if isinstance(expression, pyvex.expr.Get):
            sl = self.register_slice(expression.offset, type_.bits)
            read_type = ValueType.bv(type_.bits)
            result = self.ref(read_type)
            self.effects.append(ReadRegister(self.origin.id, result, sl))
            if sl.bit_offset==0 and sl.width_bits==sl.register_width_bits and sl.register in self.register_constants:
                self.constant_values[result.id]=self.register_constants[sl.register]
            return self.compute(ValueOp.EQ, (result, Constant(1, read_type)), type_) if type_.kind == TypeKind.BOOL else result
        if isinstance(expression, pyvex.expr.Load):
            address = self.ptr(self.expr(expression.addr))
            result = self.ref(type_)
            self.effects.append(LoadEffect(self.origin.id, result, address, type_.bits,
                self.endian(expression.end), self.truth))
            return result
        if isinstance(expression, pyvex.expr.ITE):
            # VEX is pure at this point: never evaluate nested memory branches
            # unconditionally. Such a tree needs guarded lowering not present v1.
            if any(self.has_load(e) for e in (expression.iftrue, expression.iffalse)):
                raise UnsupportedVEX('Iex_ITE', 'Nested conditional memory evaluation requires guarded lowering')
            return self.compute(ValueOp.IF, (self.expr(expression.cond), self.expr(expression.iftrue),
                                            self.expr(expression.iffalse)), type_)
        if isinstance(expression, pyvex.expr.CCall):
            name = expression.cee.name
            allowed = {'armg_calculate_condition', 'armg_calculate_flags_nzcv',
                       'armg_calculate_flag_n', 'armg_calculate_flag_z',
                       'armg_calculate_flag_c', 'armg_calculate_flag_v'}
            if self.native_arch.name.startswith('ARM') and name in allowed and len(expression.args) == 4:
                try:return self.arm_helper(name, tuple(self.expr(a) for a in expression.args))
                except ValueError as error:raise UnsupportedVEX('Iex_CCall:'+name, str(error)) from error
            raise UnsupportedVEX('Iex_CCall:'+name, 'Pure helper has no validated scalar expansion')
        if isinstance(expression, (pyvex.expr.Unop, pyvex.expr.Binop)):
            args = tuple(self.expr(arg) for arg in expression.args)
            op = expression.op
            shift = re.fullmatch(r'Iop_(Shl|Shr|Sar)(8|16|32|64)', op)
            if shift:
                return self.scalar_shift(shift[1], args[0], args[1])
            if op in ('Iop_Clz32', 'Iop_Clz64'):
                return self.scalar_clz(args[0])
            ordinary = re.fullmatch(r'Iop_(Add|Sub|Mul|And|Or|Xor)(\d+)', op)
            if ordinary:
                if type_.kind == TypeKind.BOOL:
                    if ordinary[1] == 'And':
                        return self.compute(ValueOp.IF, (args[0], args[1], Constant(False, type_)), type_)
                    if ordinary[1] == 'Or':
                        return self.compute(ValueOp.IF, (args[0], Constant(True, type_), args[1]), type_)
                    if ordinary[1] == 'Xor':
                        equal = self.compute(ValueOp.EQ, args, type_)
                        return self.compute(ValueOp.NOT, (equal,), type_)
                    raise UnsupportedVEX(op, 'One-bit arithmetic has no validated lowering')
                return self.compute({'Add': ValueOp.ADD, 'Sub': ValueOp.SUB, 'Mul': ValueOp.MUL,
                    'And': ValueOp.AND, 'Or': ValueOp.OR, 'Xor': ValueOp.XOR}[ordinary[1]], args, type_)
            compare = re.fullmatch(r'Iop_Cmp(EQ|NE|LT|LE)(\d+)([US]?)', op)
            if compare:
                kind = compare[1]
                base = ValueOp.EQ if kind in ('EQ', 'NE') else ValueOp.SLT if compare[3] == 'S' else ValueOp.ULT
                if kind == 'LE':
                    value = self.compute(base, tuple(reversed(args)), ValueType.boolean())
                    return self.compute(ValueOp.NOT, (value,), ValueType.boolean())
                value = self.compute(base, args, ValueType.boolean())
                return self.compute(ValueOp.NOT, (value,), type_) if kind == 'NE' else value
            convert = re.fullmatch(r'Iop_(\d+)([US]?)to(\d+)', op)
            if convert:
                source, target = int(convert[1]), int(convert[3])
                arg = args[0]
                if source == 1 and arg.type.kind == TypeKind.BOOL:
                    raw = self.compute(ValueOp.IF, (arg, Constant(1, ValueType.bv(1)), Constant(0, ValueType.bv(1))), ValueType.bv(1))
                    args = (raw,)
                if target == 1:
                    low = self.compute(ValueOp.EXTRACT, args, ValueType.bv(1), (0, 0))
                    return self.compute(ValueOp.EQ, (low, Constant(1, ValueType.bv(1))), type_)
                if target < source:
                    return self.compute(ValueOp.EXTRACT, args, type_, (target - 1, 0))
                if target > source:
                    return self.compute(ValueOp.SIGN_EXTEND if convert[2] == 'S' else ValueOp.ZERO_EXTEND,
                                        args, type_, (target - source,))
                return self.compute(ValueOp.COPY, args, type_)
            high = re.fullmatch(r'Iop_(\d+)HIto(\d+)', op)
            if high:
                return self.compute(ValueOp.EXTRACT, args, type_, (int(high[1]) - 1, int(high[1]) - int(high[2])))
            if re.fullmatch(r'Iop_\d+HLto\d+', op):
                return self.compute(ValueOp.CONCAT, args, type_)
            if op == 'Iop_Not1':
                return self.compute(ValueOp.NOT, args, type_)
            invert = re.fullmatch(r'Iop_Not(\d+)', op)
            if invert:
                return self.compute(ValueOp.XOR, args + (Constant((1 << type_.bits) - 1, type_),), type_)
            raise UnsupportedVEX(op, 'Scalar operation is not in the validated CIR v1 lowering subset')
        raise UnsupportedVEX(expression.tag, 'Expression class has no validated lowering')

    @staticmethod
    def has_load(expression):
        if isinstance(expression, pyvex.expr.Load):
            return True
        children = list(getattr(expression, 'args', ()))
        if isinstance(expression, pyvex.expr.ITE):
            children += [expression.cond, expression.iftrue, expression.iffalse]
        return any(VEXLowerer.has_load(a) for a in children)

    @staticmethod
    def endian(value):
        if value not in ('Iend_LE', 'Iend_BE'):
            raise UnsupportedVEX(value, 'Unknown memory endianness')
        return Endian.LITTLE if value == 'Iend_LE' else Endian.BIG

    def unknown(self, error, statement=None):
        self.unsupported.add(error.opcode)
        if isinstance(statement, pyvex.stmt.WrTmp):
            # A pure value failure cannot write guest memory or unrelated
            # registers. Its missing result may affect subsequent control.
            self.effects.append(UnknownEffect(self.origin.id, error.opcode, error.detail, (), (), True))
        elif isinstance(statement, pyvex.stmt.Put):
            width=int(statement.data.result_type(self.vex.tyenv)[5:])
            target=self.register_slice(statement.offset, width).register
            self.effects.append(UnknownEffect(self.origin.id, error.opcode, error.detail, (), (target,), target in ('pc', 'ip', 'rip', 'eip')))
            self.register_constants.pop(target, None)
        elif isinstance(statement, (pyvex.stmt.Store, pyvex.stmt.StoreG)):
            self.effects.append(UnknownEffect(self.origin.id, error.opcode, error.detail, ('*',), (), False))
        else:
            self.effects.append(UnknownEffect(self.origin.id, error.opcode, error.detail))
            self.register_constants.clear()

    def finish_block(self):
        self.blocks.append(CIRBlock(self.current_id, tuple(self.effects)))
        self.effects = []

    def target(self, absolute):
        normalized = absolute & ~1 if self.mode == 'thumb' else absolute
        known = self.starts.get(normalized)
        if known is not None:
            return known
        if normalized not in self.external_stubs:
            anchor = normalized if self.base <= normalized < 1 << self.arch.address_bits else self.instruction
            bid = self.new_block_id(anchor, self.mode)
            self.external_stubs[normalized] = (bid, absolute)
        return self.external_stubs[normalized][0]

    def statement(self, statement):
        if isinstance(statement, (pyvex.stmt.IMark, pyvex.stmt.NoOp)):
            return 'metadata'
        if isinstance(statement, pyvex.stmt.WrTmp):
            value = self.expr(statement.data)
            result = self.ref(value.type, 't')
            self.effects.append(Compute(self.origin.id, result, ValueOp.COPY, (value,)))
            self.tmps[statement.tmp] = result
            known=self.known_constant(value)
            if known is not None:self.constant_values[result.id]=known
        elif isinstance(statement, pyvex.stmt.Put):
            value = self.expr(statement.data)
            if value.type.kind == TypeKind.BOOL:
                value = self.compute(ValueOp.IF, (value, Constant(1, ValueType.bv(1)), Constant(0, ValueType.bv(1))), ValueType.bv(1))
            sl = self.register_slice(statement.offset, value.type.bits)
            policy = (RegisterWritePolicy.FULL if sl.bit_offset == 0 and sl.width_bits == sl.register_width_bits
                      else RegisterWritePolicy.PRESERVE_OTHERS)
            self.effects.append(WriteRegister(self.origin.id, sl, value, policy, self.truth))
            known=self.known_constant(value)
            self.register_constants.pop(sl.register, None)
            if policy==RegisterWritePolicy.FULL and known is not None:self.register_constants[sl.register]=known
        elif isinstance(statement, pyvex.stmt.Store):
            addr, data = self.ptr(self.expr(statement.addr)), self.expr(statement.data)
            self.effects.append(StoreEffect(self.origin.id, addr, data, data.type.bits,
                                            self.endian(statement.end), self.truth))
        elif isinstance(statement, pyvex.stmt.StoreG):
            # Addresses/data in a guarded statement must be pure (VEX normal form).
            if any(self.has_load(e) for e in (statement.addr, statement.data)):
                raise UnsupportedVEX('Ist_StoreG', 'Nested guarded memory expressions are unsupported')
            guard = self.expr(statement.guard)
            addr, data = self.ptr(self.expr(statement.addr)), self.expr(statement.data)
            self.effects.append(StoreEffect(self.origin.id, addr, data, data.type.bits, self.endian(statement.end), guard))
        elif isinstance(statement, pyvex.stmt.LoadG):
            if any(self.has_load(e) for e in (statement.addr, statement.alt)):
                raise UnsupportedVEX('Ist_LoadG', 'Nested conditional memory expressions are unsupported')
            guard, alt = self.expr(statement.guard), self.expr(statement.alt)
            native_in, native_out = statement.cvt_types
            width_in, width_out = pyvex.get_type_size(native_in), pyvex.get_type_size(native_out)
            if not re.fullmatch(r'ILGop_(Ident\d+|\d+[US]to\d+)', statement.cvt):
                raise UnsupportedVEX(statement.cvt, 'Unsupported guarded load conversion')
            loaded = self.ref(ValueType.bv(width_in))
            # Establish a defined value when guard is false, without loading.
            self.effects.append(Compute(self.origin.id, loaded, ValueOp.COPY, (Constant(0, loaded.type),)))
            self.effects.append(LoadEffect(self.origin.id, loaded, self.ptr(self.expr(statement.addr)), width_in,
                                           self.endian(statement.end), guard))
            converted = loaded if width_in == width_out else self.compute(
                ValueOp.SIGN_EXTEND if 'Sto' in statement.cvt else ValueOp.ZERO_EXTEND,
                (loaded,), ValueType.bv(width_out), (width_out - width_in,))
            self.tmps[statement.dst] = self.compute(ValueOp.IF, (guard, converted, alt), alt.type)
        elif isinstance(statement, pyvex.stmt.Exit):
            if statement.jumpkind != 'Ijk_Boring':
                raise UnsupportedVEX('Ist_Exit:' + statement.jumpkind, 'Exceptional side exit is not modeled by CIR v1')
            guard = self.expr(statement.guard)
            continuation = self.new_block_id(self.instruction, self.mode)
            self.effects.append(BranchEffect(self.origin.id, guard, self.target(statement.dst.value), continuation))
            self.finish_block()
            self.current_id = continuation
        else:
            raise UnsupportedVEX(statement.tag, 'Atomic/helper/barrier/indexed-register effect lacks exact CIR v1 semantics; havoc all state')
        return 'lowered'

    def lower_function(self, specification, chunks):
        self.fid = FunctionId(self.binary, self.rva(specification.address))
        self.values, self.blocks, self.external_stubs = [], [], {}
        self.variants = Counter()
        self.starts = {chunk.start: self.new_block_id(chunk.start, chunk.mode) for chunk in chunks}
        for chunk in chunks:
            self.current_id, self.mode = self.starts[chunk.start], chunk.mode
            self.vex, self.tmps, self.effects = chunk.vex, {}, []
            self.constant_values, self.register_constants={}, {}
            self.instruction = chunk.start
            self.truth = Constant(True, ValueType.boolean())
            before = len(self.blocks)
            if chunk.vex is None:
                opcode = 'InputBoundary' if chunk.failure.startswith('InputBoundary:') else 'LiftFailure'
                self.set_origin(opcode, None)
                self.unknown(UnsupportedVEX(opcode, chunk.failure))
                self.coverage.append(self.coverage_row(chunk, None, opcode, 'unsupported', chunk.failure, 'lift'))
                self.finish_block()
            else:
                for index, statement in enumerate(chunk.vex.statements):
                    if isinstance(statement, pyvex.stmt.IMark):
                        self.instruction = statement.addr
                    self.set_origin(statement.tag, index)
                    if isinstance(statement, pyvex.stmt.Exit):
                        if statement.jumpkind == 'Ijk_Boring':
                            self.target(statement.dst.value)
                        self.native_control.append({'function': specification.address, 'irsb': chunk.start,
                            'statement_index': index, 'origin': self.origin.id, 'kind': statement.jumpkind,
                            'target': statement.dst.value, 'guard_class': statement.guard.tag})
                    saved = (len(self.effects), len(self.values), dict(self.tmps),
                             dict(self.constant_values), dict(self.register_constants))
                    detail = ''
                    try:
                        self.count_expressions(statement)
                        status = self.statement(statement)
                    except UnsupportedVEX as error:
                        length, value_length, self.tmps, self.constant_values, self.register_constants = saved
                        del self.effects[length:]
                        del self.values[value_length:]
                        for name in ('tmp', 'dst', 'result', 'oldLo', 'oldHi'):
                            temp = getattr(statement, name, None)
                            if type(temp) is int:
                                self.tmps.pop(temp, None)
                        self.unknown(error, statement)
                        status, detail = 'unsupported', str(error)
                    self.coverage.append(self.coverage_row(chunk, index, statement.tag, status, detail))
                self.set_origin('Next:' + chunk.vex.jumpkind, len(chunk.vex.statements))
                self.native_control.append({'function': specification.address, 'irsb': chunk.start,
                    'statement_index': len(chunk.vex.statements), 'origin': self.origin.id, 'kind': chunk.vex.jumpkind,
                    'target': chunk.vex.next.con.value if isinstance(chunk.vex.next, pyvex.expr.Const) else None,
                    'target_class': chunk.vex.next.tag})
                try:
                    if chunk.vex.jumpkind == 'Ijk_Call':
                        target = self.expr(chunk.vex.next)
                        # IDA names are provenance hints, not proof that a call
                        # is external or direct. Keep the native target semantics.
                        known=self.known_constant(target)
                        if known is not None and known.value >= self.base:
                            call_target = DirectTarget(FunctionId(self.binary, self.rva(known.value)))
                        else:
                            call_target = IndirectTarget(self.ptr(target))
                        arguments=[]
                        for name in self.abi.argument_registers:
                            result=self.ref(ValueType.bv(self.arch.pointer_bits), 'arg')
                            self.effects.append(ReadRegister(self.origin.id, result,
                                RegisterSlice(name, 0, self.arch.pointer_bits, self.arch.pointer_bits)))
                            arguments.append(result)
                        results=tuple(self.ref(ValueType.bv(self.arch.pointer_bits), 'ret') for _ in self.abi.return_registers)
                        footprint=(CallFootprint(clobbered_registers=self.abi.caller_saved, unknown=False,
                            reason='AAPCS32 nonvolatile registers preserved; unknown memory writes remain *')
                            if self.abi.caller_saved else CallFootprint())
                        self.effects.append(CallEffect(self.origin.id, CallSiteId(self.origin.point), call_target,
                            tuple(arguments), results, self.abi, self.truth, footprint))
                        for name, value in zip(self.abi.return_registers, results):
                            self.effects.append(WriteRegister(self.origin.id,
                                RegisterSlice(name, 0, self.arch.pointer_bits, self.arch.pointer_bits), value,
                                RegisterWritePolicy.FULL, self.truth))
                        self.unsupported.add('CallMemoryEffects')
                        self.effects.append(JumpEffect(self.origin.id, self.target(chunk.end)))
                    elif chunk.vex.jumpkind == 'Ijk_Ret':
                        results=[]
                        for name in self.abi.return_registers:
                            result=self.ref(ValueType.bv(self.arch.pointer_bits), 'return')
                            self.effects.append(ReadRegister(self.origin.id, result,
                                RegisterSlice(name, 0, self.arch.pointer_bits, self.arch.pointer_bits)))
                            results.append(result)
                        self.effects.append(ReturnEffect(self.origin.id, tuple(results), self.truth))
                    elif chunk.vex.jumpkind == 'Ijk_Boring':
                        target = self.expr(chunk.vex.next)
                        self.effects.append(JumpEffect(self.origin.id,
                            self.target(target.value) if isinstance(target, Constant) and target.value >= self.base else self.ptr(target)))
                    else:
                        raise UnsupportedVEX('Next:' + chunk.vex.jumpkind, 'Unmodeled terminal control effect')
                    self.coverage.append(self.coverage_row(chunk, len(chunk.vex.statements),
                        'Next:' + chunk.vex.jumpkind, 'lowered', kind='terminal'))
                except UnsupportedVEX as error:
                    self.unknown(error)
                    self.coverage.append(self.coverage_row(chunk, len(chunk.vex.statements), error.opcode,
                                                           'unsupported', str(error), 'terminal'))
                self.finish_block()
            self.mappings.append({'function': specification.address, 'source_start': chunk.source_start,
                'source_end': chunk.source_end, 'irsb_start': chunk.start, 'irsb_end': chunk.end,
                'mode': chunk.mode, 'byte_sha256': chunk.byte_sha256,
                'cir_blocks': [b.id.token for b in self.blocks[before:]], 'lift_failure': chunk.failure})
        for _, (bid, target) in sorted(self.external_stubs.items()):
            self.current_id, self.instruction = bid, self.base + bid.rva
            self.set_origin('ExternalControlBoundary', None)
            self.blocks.append(CIRBlock(bid, (JumpEffect(self.origin.id,
                Constant(target, ValueType.pointer(self.arch.pointer_bits))),)))
        return CIRFunction(self.fid, tuple(self.values), tuple(self.blocks), self.starts[specification.address], self.abi)

    def coverage_row(self, chunk, index, opcode, status, detail='', kind='statement'):
        return {'function': chunk.function.address, 'source_block': chunk.source_start, 'irsb': chunk.start,
                'statement_index': index, 'instruction': self.instruction, 'origin': self.origin.id,
                'source_opcode': opcode, 'status': status, 'detail': detail, 'kind': kind,
                'imark_delta': getattr(chunk.vex.statements[index], 'delta', None)
                    if chunk.vex is not None and type(index) is int and index < len(chunk.vex.statements) else None}

    def lower(self, specifications, chunks, metadata=None):
        functions = tuple(self.lower_function(spec, [c for c in chunks if c.function.address == spec.address])
                          for spec in specifications)
        assessment = Assessment(unsupported_ops=tuple(sorted(self.unsupported)), diagnostics=(
            'Bounded input lifting; full function/ABI/reachability coverage is not established',))
        module = CIRModule(self.producer, self.arch, self.arch.endian, self.binary.sha256,
                           functions, tuple(self.origins), ('typed-effects',), assessment)
        metadata = dict(metadata or {})
        metadata['image_base'] = self.base
        metadata.update(expression_histogram=dict(self.expression_histogram), native_control_flow=self.native_control)
        metadata['source_functions'] = [{'address': s.address, 'name': s.name,
            'blocks': [vars(b) for b in s.blocks], 'edges': list(s.edges), 'call_hints': [vars(c) for c in s.calls]}
            for s in specifications]
        return FrontendResult(module, tuple(self.coverage), tuple(self.mappings), metadata)
