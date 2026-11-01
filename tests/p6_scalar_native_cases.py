"""Independent installed-angr scalar oracle; run in a guarded native probe."""
import random
import unittest
import archinfo
import claripy
import pyvex
from angr.engines.vex.claripy import ccall, irop
from emtaint.frontends.arm_scalar import ARMScalarLowering
from emtaint.core.contracts import Constant, ValueType, TypeKind
from emtaint.ir.canonical import ValueOp as O, UnknownEffect,Compute,ReadRegister
from p4_native_cases import lower_native


class EvaluateExpansion(ARMScalarLowering):
    """Execute emitted CIR with Python integers, independently of P5 DAG."""
    def compute(self,op,args,type_,params=()):
        a=[x.value for x in args]
        if op==O.COPY:v=a[0]
        elif op==O.MUL:v=a[0]*a[1]
        elif op==O.ADD:v=a[0]+a[1]
        elif op==O.SUB:v=a[0]-a[1]
        elif op==O.AND:v=a[0]&a[1]
        elif op==O.OR:v=a[0]|a[1]
        elif op==O.XOR:v=a[0]^a[1]
        elif op==O.EQ:v=a[0]==a[1]
        elif op==O.NOT:v=not a[0]
        elif op==O.ULT:v=a[0]<a[1]
        elif op==O.IF:v=a[1] if a[0] else a[2]
        elif op==O.EXTRACT:v=(a[0]>>params[1])&((1<<type_.bits)-1)
        elif op==O.ZERO_EXTEND:v=a[0]
        elif op==O.SIGN_EXTEND:
            w=args[0].type.bits;v=a[0]-(1<<w) if a[0]&(1<<(w-1)) else a[0]
        else:raise AssertionError(op)
        return Constant(v if type_.kind==TypeKind.BOOL else v% (1<<type_.bits),type_)


class ScalarNativeCases(unittest.TestCase):
    def test_shift_boundaries_against_installed_vex_backend(self):
        expand=EvaluateExpansion();rng=random.Random(601)
        for width in (8,16,32,64):
            for kind in ('Shl','Shr','Sar'):
                oracle=irop.vexop_to_simop('Iop_'+kind+str(width))
                for value in (0,1,1<<(width-1),(1<<width)-1,*[rng.getrandbits(width) for _ in range(8)]):
                    for amount in (0,1,width-1,width,width+1,127,255):
                        got=expand.scalar_shift(kind,Constant(value,ValueType.bv(width)),Constant(amount,ValueType.bv(8))).value
                        expected=oracle.calculate(claripy.BVV(value,width),claripy.BVV(amount,8))
                        self.assertEqual(got,expected.concrete_value,(width,kind,value,amount))

    def test_arm_flags_all_cc_ops_conditions_and_boundaries(self):
        expand=EvaluateExpansion();rng=random.Random(602)
        pairs=[(0,0),(0xffffffff,1),(0x7fffffff,1),(0x80000000,1),(0,1),(0x80000000,0xffffffff)]
        pairs += [(rng.getrandbits(32),rng.getrandbits(32)) for _ in range(12)]
        for cc in range(8):
            for a,b in pairs:
                for carry in range(4):
                    # VEX invariants: ADC/SBB oldC is one bit; LOGIC's
                    # shifter carry and oldV are one bit.
                    third=carry&1 if cc in (3,4,5) else carry
                    second=b&1 if cc==5 else b
                    for name in ('armg_calculate_flag_n','armg_calculate_flag_z','armg_calculate_flag_c',
                                 'armg_calculate_flag_v','armg_calculate_flags_nzcv','armg_calculate_condition'):
                        conditions=range(15) if name.endswith('condition') else (0,)
                        for condition in conditions:
                            raw=(cc|(condition<<4),a,second,third)
                            expected=getattr(ccall,name)(None,*[claripy.BVV(x,32) for x in raw]).concrete_value
                            got=expand.arm_helper(name,tuple(Constant(x,ValueType.bv(32)) for x in raw)).value
                            self.assertEqual(got,expected,(name,raw))

    def test_real_ccall_and_shifts_lower_without_havoc(self):
        c=lambda x:pyvex.expr.Const(pyvex.const.U32(x))
        helper=pyvex.expr.CCall('Ity_I32',pyvex.IRCallee(0,'armg_calculate_condition',0),[c(0x12),c(1),c(2),c(0)])
        result,_=lower_native((pyvex.stmt.WrTmp(0,helper),),('Ity_I32',),arch=archinfo.ArchARMEL())
        self.assertFalse(any(isinstance(e,UnknownEffect) for b in result.module.functions[0].blocks for e in b.effects))
        self.assertNotIn('Iex_CCall',result.module.assessment.unsupported_ops)

    def test_clz_nonzero_independent_oracle(self):
        expand=EvaluateExpansion()
        for width in (32,64):
            for value in (1,2,3,1<<(width-1),(1<<width)-1,0x8001):
                self.assertEqual(expand.scalar_clz(Constant(value,ValueType.bv(width))).value,width-value.bit_length())

    def test_dynamic_private_cc_dispatch_emitted_cir(self):
        arch=archinfo.ArchARMEL();condition=12
        reg=lambda name:pyvex.expr.Get(arch.registers[name][0],'Ity_I32')
        packed=pyvex.expr.Binop('Iop_Or32',[reg('cc_op'),pyvex.expr.Const(pyvex.const.U32(condition<<4))])
        helper=pyvex.expr.CCall('Ity_I32',pyvex.IRCallee(0,'armg_calculate_condition',0),
            [packed,reg('cc_dep1'),reg('cc_dep2'),reg('cc_ndep')])
        result,_=lower_native((pyvex.stmt.WrTmp(0,helper),),('Ity_I32',),arch=arch)
        self.assertFalse(result.module.assessment.unsupported_ops)
        effects=result.module.functions[0].blocks[0].effects
        for cc in range(8):
            registers={'cc_op':cc,'cc_dep1':0x80000000,'cc_dep2':1,'cc_ndep':1}
            values={};executor=EvaluateExpansion()
            for effect in effects:
                if isinstance(effect,ReadRegister):
                    values[effect.result.id]=Constant(registers[effect.source.register],effect.result.type)
                elif isinstance(effect,Compute):
                    operands=tuple(x if isinstance(x,Constant) else values[x.id] for x in effect.args)
                    values[effect.result.id]=executor.compute(effect.op,operands,effect.result.type,effect.params)
            answer=values[[e.result.id for e in effects if isinstance(e,Compute)][-1]].value
            expected=ccall.armg_calculate_condition(None,*[claripy.BVV(x,32) for x in
                (cc|(condition<<4),0x80000000,1,1)]).concrete_value
            self.assertEqual(answer,expected,cc)

    def test_unknown_pure_value_does_not_havoc_unrelated_state(self):
        arch=archinfo.ArchARMEL()
        value=pyvex.expr.Binop('Iop_DivU32',[pyvex.expr.Const(pyvex.const.U32(8)),pyvex.expr.Const(pyvex.const.U32(2))])
        result,_=lower_native((pyvex.stmt.Put(value,arch.registers['r3'][0]),),arch=arch)
        unknown=[e for b in result.module.functions[0].blocks for e in b.effects if isinstance(e,UnknownEffect)]
        self.assertEqual(len(unknown),1)
        self.assertEqual(unknown[0].may_write_regions,())
        self.assertEqual(unknown[0].may_write_registers,('r3',))


if __name__=='__main__':unittest.main()
