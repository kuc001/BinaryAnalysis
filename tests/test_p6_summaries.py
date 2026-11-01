"""Actual callee DAG recipes bind caller arguments in a fresh memory scope."""
import unittest
import test_p6_demand as fixtures
from emtaint.core import CallSiteId
from emtaint.core.contracts import ValueRef,Constant,ValueType,ScopedId
from emtaint.ir.canonical import Compute,ValueOp,LoadEffect,StoreEffect,CallEffect,DirectTarget
from emtaint.analysis.framework.summaries import compile_recipe


class RecipeTests(unittest.TestCase):
    def test_stack_argument_uses_actual_caller_sp_and_reaching_store(self):
        make=fixtures.DemandTests().make;t=fixtures.t;ptr=fixtures.ptr
        sp=ValueRef('sp',t);address=ValueRef('address',ptr);out=ValueRef('out',t)
        callee,_,_=make(((fixtures.get('sp',sp),Compute('o0',address,ValueOp.ADD,(Constant(0,ptr),sp)),LoadEffect('o0',out,address,32,fixtures.Endian.LITTLE,fixtures.truth)),),function_rva=0x100,session='callee')
        recipe=compile_recipe(callee,callee.value(out));self.assertEqual(recipe.argument_uses,(4,))
        prototype,_,_=make(((),),session='caller')
        call=CallEffect('o0',CallSiteId(prototype.port.point('o0')),DirectTarget(callee.function.function_id),(),(out,),prototype.function.abi,fixtures.truth)
        store=StoreEffect('o0',Constant(0x7fffffff,ptr),Constant(0x3000,t),32,fixtures.Endian.LITTLE,fixtures.truth)
        caller,_,_=make(((store,call),),session='caller')
        self.assertEqual({caller.port.concrete(x) for x in recipe.instantiate(caller,call)},{0x3000})

    def test_argument_return_alias_substitution(self):
        make=fixtures.DemandTests().make;t=fixtures.t
        a=ValueRef('arg',t);result=ValueRef('result',t)
        callee,_,_=make(((fixtures.get('r0',a),Compute('o0',result,ValueOp.ADD,(a,Constant(4,t)))),),function_rva=0x100,session='callee')
        recipe=compile_recipe(callee,callee.value(result),provenance=('real fixture callee',))
        self.assertEqual(recipe.argument_uses,(0,))
        caller,_,_=make(((),),session='caller')
        call=CallEffect('o0',CallSiteId(caller.port.point('o0')),DirectTarget(callee.function.function_id),
                        (Constant(0x1000,t),),(result,),caller.function.abi,fixtures.truth)
        caller.defs[result.id]=(caller.function.entry,0,call)
        values=recipe.instantiate(caller,call)
        self.assertEqual({caller.port.concrete(x) for x in values},{0x1004})
        self.assertTrue(all(x.scope.session_id=='caller' for x in values))
        self.assertTrue(all(not isinstance(n.value,ScopedId) for n in recipe.nodes))

    def test_callee_load_reads_caller_reaching_store_version(self):
        make=fixtures.DemandTests().make;t=fixtures.t;ptr=fixtures.ptr
        a=ValueRef('arg',t);address=ValueRef('address',ptr);value=ValueRef('value',t)
        callee,_,_=make(((fixtures.get('r0',a),Compute('o0',address,ValueOp.ADD,(Constant(0,ptr),a)),
                         LoadEffect('o0',value,address,32,fixtures.Endian.LITTLE,fixtures.truth)),),function_rva=0x100,session='callee')
        recipe=compile_recipe(callee,callee.value(value))
        store=StoreEffect('o0',Constant(0x1000,ptr),Constant(0x3000,t),32,fixtures.Endian.LITTLE,fixtures.truth)
        caller,_,_=make(((store,),),session='caller')
        call=CallEffect('o0',CallSiteId(caller.port.point('o0')),DirectTarget(callee.function.function_id),
                        (Constant(0x1000,t),),(value,),caller.function.abi,fixtures.truth)
        caller.defs[value.id]=(caller.function.entry,1,call)
        values=recipe.instantiate(caller,call)
        self.assertEqual({caller.port.concrete(x) for x in values},{0x3000})
        self.assertGreater(caller.port.calls['write'],0)
        self.assertGreater(len(caller.port.engine.versions),1)

    def test_callee_argument_definition_updates_caller_memory(self):
        make=fixtures.DemandTests().make;t=fixtures.t;ptr=fixtures.ptr
        argument=ValueRef('arg',t);address=ValueRef('address',ptr);out=ValueRef('out',t)
        effect=StoreEffect('o0',address,Constant(0x3000,t),32,fixtures.Endian.LITTLE,fixtures.truth)
        callee,_,_=make(((fixtures.get('r0',argument),Compute('o0',address,ValueOp.ADD,(Constant(0,ptr),argument)),effect),),
                        function_rva=0x100,session='callee')
        recipe=compile_recipe(callee,(),stores=((effect,callee.value(address),callee.value(effect.value)),))
        prototype,_,_=make(((),),session='caller')
        call=CallEffect('o0',CallSiteId(prototype.port.point('o0')),DirectTarget(callee.function.function_id),
                        (Constant(0x1000,t),),(),prototype.function.abi,fixtures.truth)
        load=LoadEffect('o0',out,Constant(0x1000,ptr),32,fixtures.Endian.LITTLE,fixtures.truth)
        caller,_,_=make(((call,load),),session='caller');caller.summaries[callee.function.function_id]=recipe
        self.assertEqual({caller.port.concrete(x) for x in caller.value(out)},{0x3000})
        self.assertGreater(caller.port.calls['resolve_definition'],0)
        self.assertTrue(any('argument-def' in rule for rule in caller.rules))


if __name__=='__main__':unittest.main()
