"""Pure scalar expansions into the existing CIR v1 operations.

ARM flags follow VEX's private CC_OP domain (0..7), not host integer flags.
No native helper/AST is retained by CIR. Clz(0) is undefined in VEX; our
deterministic extension returns width, without claiming VEX defines that case.
"""
from emtaint.core.contracts import Constant, ValueType
from emtaint.ir.canonical import ValueOp as O


class ARMScalarLowering:
    def scalar_shift(self, kind, value, amount):
        width = value.type.bits
        def fixed(v, k):
            if k == 0:
                return v
            if kind == 'Shl':
                return self.compute(O.MUL, (v, Constant(1 << k, v.type)), v.type)
            part = self.compute(O.EXTRACT, (v,), ValueType.bv(width-k), (width-1, k))
            return self.compute(O.SIGN_EXTEND if kind == 'Sar' else O.ZERO_EXTEND,
                                (part,), v.type, (k,))
        if isinstance(amount, Constant) and amount.value < width:
            return fixed(value, amount.value)
        # Barrel shift, logarithmic in width; the final test also covers all
        # oversized shift counts. Counts are unsigned, as in VEX's I8 operand.
        result = value
        for bit in range((width-1).bit_length()):
            mask = Constant(1 << bit, amount.type)
            masked = self.compute(O.AND, (amount, mask), amount.type)
            enabled = self.compute(O.EQ, (masked, mask), ValueType.boolean())
            result = self.compute(O.IF, (enabled, fixed(result, 1 << bit), result), value.type)
        in_range = self.compute(O.ULT, (amount, Constant(width, amount.type)), ValueType.boolean())
        overflow = fixed(value, width-1) if kind == 'Sar' else Constant(0, value.type)
        return self.compute(O.IF, (in_range, result, overflow), value.type)

    def scalar_clz(self, value):
        result = Constant(value.type.bits, value.type)
        for bit in range(value.type.bits):
            masked = self.compute(O.AND, (value, Constant(1 << bit, value.type)), value.type)
            zero = self.compute(O.EQ, (masked, Constant(0, value.type)), ValueType.boolean())
            result = self.compute(O.IF, (zero, result, Constant(value.type.bits-1-bit, value.type)), value.type)
        return result

    def arm_helper(self, name, args):
        t = ValueType.bv(32)
        boolean = ValueType.boolean()
        c = lambda x: Constant(x, t)
        op = lambda kind, *values: self.compute(kind, values, t)
        eq = lambda a, b: self.compute(O.EQ, (a, b), boolean)
        ult = lambda a, b: self.compute(O.ULT, (a, b), boolean)
        choose = lambda g, a, b: self.compute(O.IF, (g, a, b), t)
        inv = lambda a: op(O.XOR, a, c(1))
        bit = lambda a, k: self.compute(O.ZERO_EXTEND,
            (self.compute(O.EXTRACT, (a,), ValueType.bv(1), (k, k)),), t, (31,))
        z = lambda a: choose(eq(a, c(0)), c(1), c(0))
        packed, a, b, carry = args
        known=getattr(self, 'known_constant', lambda x:x if isinstance(x, Constant) else None)(packed)
        known_cc=(known.value&15 if name=='armg_calculate_condition' else known.value) if known else None
        known_condition=known.value>>4 if known and name=='armg_calculate_condition' else None
        cc = op(O.AND, packed, c(15)) if name == 'armg_calculate_condition' else packed
        add = op(O.ADD, a, b)
        sub = op(O.SUB, a, b)
        adc = op(O.ADD, add, carry)
        sbb = op(O.SUB, sub, inv(carry))
        ns = [lambda:bit(a, 31), lambda:bit(add, 31), lambda:bit(sub, 31), lambda:bit(adc, 31), lambda:bit(sbb, 31),
              lambda:bit(a, 31), lambda:bit(a, 31), lambda:bit(b, 31)]
        zs = [lambda:bit(a, 30), lambda:z(add), lambda:z(sub), lambda:z(adc), lambda:z(sbb), lambda:z(a), lambda:z(a), lambda:z(op(O.OR, a, b))]
        ge = lambda x, y: choose(ult(x, y), c(0), c(1))
        cs = [lambda:bit(a, 29), lambda:choose(ult(add, a), c(1), c(0)), lambda:ge(a, b),
              lambda:choose(eq(carry, c(0)), choose(ult(adc, a), c(1), c(0)), ge(a, adc)),
              lambda:choose(eq(carry, c(0)), choose(ult(b, a), c(1), c(0)), ge(a, b)),
              lambda:b, lambda:bit(carry, 1), lambda:bit(carry, 1)]
        overflow_add = lambda r: bit(op(O.AND, op(O.XOR, r, a), op(O.XOR, r, b)), 31)
        overflow_sub = lambda r: bit(op(O.AND, op(O.XOR, a, b), op(O.XOR, a, r)), 31)
        vs = [lambda:bit(a, 28), lambda:overflow_add(add), lambda:overflow_sub(sub), lambda:overflow_add(adc), lambda:overflow_sub(sbb),
              lambda:carry, lambda:bit(carry, 0), lambda:bit(carry, 0)]
        def select(values):
            # CC_OP=7 is the final valid case. Native VEX owns the invariant
            # that private cc_op is in 0..7; no program input is used as cc_op.
            if known_cc is not None:
                if not 0<=known_cc<8:raise ValueError('Invalid architectural ARM CC_OP')
                return values[known_cc]()
            result = values[7]()
            for index in range(6, -1, -1):
                result = choose(eq(cc, c(index)), values[index](), result)
            return result
        flags={}
        def flag(key):
            if key not in flags:flags[key]=select({'n':ns, 'z':zs, 'c':cs, 'v':vs}[key])
            return flags[key]
        if name.startswith('armg_calculate_flag_'):
            return flag(name[-1])
        if name == 'armg_calculate_flags_nzcv':
            parts = [op(O.MUL, bit(flag(key), 0), c(1 << shift)) for key, shift in (('n', 31), ('z', 30), ('c', 29), ('v', 28))]
            return op(O.OR, op(O.OR, parts[0], parts[1]), op(O.OR, parts[2], parts[3]))
        condition = self.scalar_shift('Shr', packed, c(4))
        bases = [lambda:flag('z'), lambda:flag('c'), lambda:flag('n'), lambda:flag('v'),
                 lambda:op(O.AND, flag('c'), inv(flag('z'))), lambda:inv(op(O.XOR, flag('n'), flag('v'))),
                 lambda:inv(op(O.OR, flag('z'), op(O.XOR, flag('n'), flag('v'))))]
        if known_condition is not None:
            if known_condition==14:return c(1)
            if not 0<=known_condition<14:raise ValueError('Invalid architectural ARM condition')
            value=bases[known_condition//2]()
            return inv(value) if known_condition&1 else value
        result = c(1)  # AL, the only other VEX-generated condition.
        for index in range(13, -1, -1):
            value = bases[index//2]()
            if index & 1:value = inv(value)
            result = choose(eq(condition, c(index)), value, result)
        return result
