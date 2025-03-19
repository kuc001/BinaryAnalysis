import pyvex
from angr.code_location import CodeLocation

from emtaint.ir.visitors import IRVisitor
from emtaint.analysis.variables.var_type import TypeKind, EMType, PointerType, IntegerType, FunctionType, StructType, ArrayType, OtherType
from emtaint.analysis.variables.value import ValueKind
from emtaint.analysis.variables.tmp_value import TmpValue
from emtaint.analysis.variables.reg_value import RegValue
from emtaint.analysis.variables.binop_value import BinopValue
from emtaint.analysis.variables.cons_value import ConsValue
from emtaint.analysis.variables.mem_value import MemValue

from .var_node import VarNode
from .var_edge import VarEdge, EdgeKind

class PAGVisitor(IRVisitor):
    def __init__(self, ir_graph):
        super().__init__()
        self.ir_graph = ir_graph

        self._current_block_addr = None     # 当前块的地址
        self._current_stmt_addr = None     # 当前语句的地址
        self._current_stmt_idx = None      # 当前语句的索引
        self._current_loc = None           # 当前语句的CodeLocation
    
    def set_current_block_addr(self, addr):
        self._current_block_addr = addr
    
    def set_current_stmt_addr(self, addr):
        self._current_stmt_addr = addr
    
    def set_current_stmt_idx(self, idx):
        self._current_stmt_idx = idx
    
    def set_current_loc(self):
        self._current_loc = CodeLocation(self._current_block_addr, self._current_stmt_idx, ins_addr=self._current_stmt_addr)
        
    def visit_put(self, put):
        raise NotImplementedError("visit_put")

    def visit_put_tmp(self, put_tmp):
        def_name = put_tmp.get_def()
        use_expr = put_tmp.get_use()
        use_name = use_expr.get_name()
        def_value = RegValue(def_name, None, ValueKind.Unknown, loc=self._current_loc)
        use_value = TmpValue(use_name, None, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        def_node = VarNode(def_value)
        use_node = VarNode(use_value)

        edge = VarEdge(use_node, def_node, kind=EdgeKind.Assign, stmt=put_tmp)
        def_node.in_edges.add(edge)
        use_node.out_edges.add(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return edge

    def visit_put_const(self, put_const):
        def_name = put_const.get_def()
        use_expr = put_const.get_use()
        use_cons = use_expr.get_name()
        def_value = RegValue(def_name, None, ValueKind.Unknown, loc=self._current_loc)
        use_value = ConsValue(use_cons, None, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        def_node = VarNode(def_value)
        use_node = VarNode(use_value)

        edge = VarEdge(use_node, def_node, kind=EdgeKind.Assign, stmt=put_const)
        def_node.in_edges.add(edge)
        use_node.out_edges.add(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return edge

    def visit_imark(self, imark):
        self.set_current_stmt_addr(imark.addr)
        return None
     
    def visit_puti(self, puti):
        raise NotImplementedError("visit_puti")

    def visit_wr_tmp(self, wr_tmp):
        def_name = wr_tmp.get_def()
        use_expr = wr_tmp.get_use()
        use_name = use_expr.get_name()
        
        def_value = TmpValue(def_name, None, ValueKind.Unknown, loc=self._current_loc)
        use_value = TmpValue(use_name, None, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        def_node = VarNode(def_value)
        use_node = VarNode(use_value)

        edge = VarEdge(use_node, def_node, kind=EdgeKind.Assign, stmt=wr_tmp)
        def_node.in_edges.add(edge)
        use_node.out_edges.add(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return edge
        
    def visit_wr_get(self, wr_get):
        def_name = wr_get.get_def()
        use_expr = wr_get.get_use()
        use_name = use_expr.get_name()
        
        size = use_expr.get_size()
        def_value = TmpValue(def_name, size, ValueKind.Unknown, loc=self._current_loc)
        use_value = RegValue(use_name, size, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        def_node = VarNode(def_value)
        use_node = VarNode(use_value)

        edge = VarEdge(use_node, def_node, kind=EdgeKind.Assign, stmt=wr_get)
        def_node.in_edges.add(edge)
        use_node.out_edges.add(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return edge
        
    def visit_wr_binop(self, wr_binop):
        # print(wr_binop) 
        def_name = wr_binop.get_def()
        use_expr = wr_binop.get_use()

        size = use_expr.get_size()
        def_value = TmpValue(def_name, size, ValueKind.Unknown, loc=self._current_loc)
        use_value = BinopValue(use_expr.op, use_expr.get_args_info(), size, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        def_node = VarNode(def_value)
        use_node = VarNode(use_value)

        edge = VarEdge(use_node, def_node, kind=EdgeKind.BinopAssign, stmt=wr_binop)
        def_node.in_edges.add(edge)
        use_node.out_edges.add(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return edge
        
    def visit_wr_load(self, wr_load):
        raise NotImplementedError("visit_wr_load")
    
    def visit_wr_load_cons(self, wr_load_cons):
        # print(wr_load_cons)
        def_name = wr_load_cons.get_def()
        use_expr = wr_load_cons.get_use()
        use_name = use_expr.addr.get_name()
        size = use_expr.get_size()
        def_value = TmpValue(def_name, size, ValueKind.Unknown, loc=self._current_loc)
        use_value = MemValue(use_name, size, ValueKind.MemAccess, "load", expr=use_expr, loc=self._current_loc)

        def_node = VarNode(def_value)
        use_node = VarNode(use_value)

        edge = VarEdge(use_node, def_node, kind=EdgeKind.LoadAssign, stmt=wr_load_cons)
        def_node.in_edges.add(edge)
        use_node.out_edges.add(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return edge

    def visit_wr_load_tmp(self, wr_load_tmp):
        raise NotImplementedError("visit_wr_load_tmp")
        
    def visit_wr_ite(self, wr_ite):
        raise NotImplementedError("visit_wr_ite")   
        
    def visit_wr_unop(self, wr_unop):
        raise NotImplementedError("visit_wr_unop")

    def visit_loadg(self, loadg):
        raise NotImplementedError("visit_loadg")

    def visit_storeg(self, storeg):
        raise NotImplementedError("visit_storeg")
    
    def visit_store(self, store):
        raise NotImplementedError("visit_store")

    def visit_reg_store_tmp(self, reg_store_tmp):
        def_expr = reg_store_tmp.get_def()
        use_expr = reg_store_tmp.get_use()
        use_name = use_expr.get_name()
        def_name = def_expr.get_name()
        def_value = MemValue(def_name, None, ValueKind.MemAccess, "store", expr=def_expr, loc=self._current_loc)
        use_value = TmpValue(use_name, None, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        def_node = VarNode(def_value)
        use_node = VarNode(use_value)

        edge = VarEdge(use_node, def_node, kind=EdgeKind.StoreAssign, stmt=reg_store_tmp)
        def_node.in_edges.add(edge)
        use_node.out_edges.add(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return edge

    def visit_reg_store_cons(self, reg_store_cons):
        def_expr = reg_store_cons.get_def()
        use_expr = reg_store_cons.get_use()
        use_cons = use_expr.get_name()
        def_name = def_expr.get_name()
        def_value = MemValue(def_name, None, ValueKind.MemAccess, "store", expr=def_expr, loc=self._current_loc)
        use_value = ConsValue(use_cons, None, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        def_node = VarNode(def_value)
        use_node = VarNode(use_value)

        edge = VarEdge(use_node, def_node, kind=EdgeKind.StoreAssign, stmt=reg_store_cons)
        def_node.in_edges.add(edge)
        use_node.out_edges.add(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return edge
        
    def visit_global_store_tmp(self, global_store_tmp):
        raise NotImplementedError("visit_global_store_tmp")

    def visit_global_store_cons(self, global_store_cons):
        raise NotImplementedError("visit_global_store_cons")
        
    def visit_exit(self, ext):
        raise NotImplementedError("visit_exit")

    # Expressions visitors
    def visit_binop(self, binop):
        raise NotImplementedError("visit_binop")
        
        
        