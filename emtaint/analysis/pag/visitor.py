import pyvex

from emtaint.ir.visitors import IRVisitor
from emtaint.analysis.variables.var_type import TypeKind, EMType, PointerType, IntegerType, FunctionType, StructType, ArrayType, OtherType
from emtaint.analysis.variables.value import ValueKind
from emtaint.analysis.variables.tmp_value import TmpValue
from emtaint.analysis.variables.reg_value import RegValue
from emtaint.analysis.variables.binop_value import BinopValue
from emtaint.analysis.variables.cons_value import ConsValue

class PAGVisitor(IRVisitor):
    def __init__(self):
        super().__init__()
        
    def visit_put(self, put):
        raise NotImplementedError("visit_put")

    def visit_put_tmp(self, put_tmp):
        def_name = put_tmp.get_def()
        use_expr = put_tmp.get_use()
        use_name = use_expr.get_name()
        dev_value = RegValue(def_name, None, ValueKind.Unknown)
        use_value = TmpValue(use_name, None, ValueKind.Unknown)

        return dev_value, use_value

    def visit_put_const(self, put_const):
        def_name = put_const.get_def()
        use_expr = put_const.get_use()
        use_cons = use_expr.get_cons()
        dev_value = RegValue(def_name, None, ValueKind.Unknown)
        use_value = ConsValue(use_cons, None, ValueKind.Unknown)

        return dev_value, use_value

    def visit_imark(self, imark):
        pass
     
    def visit_puti(self, puti):
        print(puti)

    def visit_wr_tmp(self, wr_tmp):
        pass
        # def_expr = wr_tmp.get_def()
        # use_expr = wr_tmp.get_use()
        # print(def_expr, use_expr)
        
    def visit_wr_get(self, wr_get):
        def_name = wr_get.get_def()
        use_expr = wr_get.get_use()
        use_name = use_expr.get_name()
        # print(def_name, use_expr)
        # if isinstance(use_expr, pyvex.expr.IRExpr):
        #     print(f"use_expr is IRExpr: {use_expr}")
        
        size = use_expr.get_size()
        dev_value = TmpValue(def_name, size, ValueKind.Unknown)
        use_value = RegValue(use_name, size, ValueKind.Unknown, expr=use_expr)

        return dev_value, use_value
        
    def visit_wr_binop(self, wr_binop):
        print(wr_binop) 
        def_name = wr_binop.get_def()
        use_expr = wr_binop.get_use()

        size = use_expr.get_size()
        dev_value = TmpValue(def_name, size, ValueKind.Unknown)
        use_value = BinopValue(use_expr.op, use_expr.get_args_info(), size, ValueKind.Unknown)

        return dev_value, use_value
        
    def visit_wr_load(self, wr_load):
        print(wr_load)
        
    def visit_wr_ite(self, wr_ite):
        print(wr_ite)   
        
    def visit_wr_unop(self, wr_unop):
        print(wr_unop)

    def visit_loadg(self, loadg):
        print(loadg)

    def visit_storeg(self, storeg):
        print(storeg)
    
    def visit_store(self, store):
        print(store)
        
    def visit_exit(self, ext):
        print(ext)

    # Expressions visitors
    def visit_binop(self, binop):
        print(binop)

        op = binop.op
        
        
        