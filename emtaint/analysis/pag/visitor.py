import logging
import pyvex

from emtaint.assembly.code_location import CodeLocation
from emtaint.ir.visitors import IRVisitor
from emtaint.analysis.variables.var_type import TypeKind, EMType, PointerType, IntegerType, FunctionType, StructType, ArrayType, OtherType
from emtaint.analysis.variables.value import ValueKind
from emtaint.analysis.variables.tmp_value import TmpValue
from emtaint.analysis.variables.reg_value import RegValue
from emtaint.analysis.variables.binop_value import BinopValue
from emtaint.analysis.variables.cons_value import ConsValue
from emtaint.analysis.variables.mem_value import MemValue
from emtaint.analysis.variables.unop_value import UnopValue
from .var_node import VarNode
from .var_edge import VarEdge, OpEdge, AssignEdge, FlowEdge, AddrEdge, EdgeKind


l = logging.getLogger(name=__name__)


class PAGVisitor(IRVisitor):
    def __init__(self, ir_graph):
        super().__init__()
        self.ir_graph = ir_graph

        self._current_block_addr = None     # 当前块的地址
        self._current_stmt_addr = None     # 当前语句的地址
        self._current_stmt_idx = None      # 当前语句的索引
        self._current_loc = None           # 当前语句的CodeLocation

        self._block_tmp_nodes = {}  # 当前块的临时变量节点
        self._tmp_to_use_node = {}  # 临时变量到使用节点的映射
    
    def set_current_block_addr(self, addr):
        self._current_block_addr = addr
    
    def set_current_stmt_addr(self, addr):
        self._current_stmt_addr = addr
    
    def set_current_stmt_idx(self, idx):
        self._current_stmt_idx = idx
    
    def set_current_loc(self):
        self._current_loc = CodeLocation(self._current_block_addr, self._current_stmt_idx, ins_addr=self._current_stmt_addr)
    
    def clear_block_tmp_nodes(self):
        self._block_tmp_nodes.clear()

    def get_tmp_node(self, name, rd_tmp=None, size=None, kind=ValueKind.Unknown):
        if name in self._block_tmp_nodes:
            node = self._block_tmp_nodes[name]
            if node.var.kind == ValueKind.Unknown:
                node.change_var_kind(kind)
            return node
        
        node = VarNode(TmpValue(name, size, kind, expr=rd_tmp, loc=self._current_loc), 1)
        self._block_tmp_nodes[name] = node
        return node
    
    def add_tmp_to_use(self, tmp_node, use_node):
        self._tmp_to_use_node[tmp_node.id] = use_node

    def get_tmp_to_use(self, tmp_node):
        return self._tmp_to_use_node[tmp_node.id] if tmp_node.id in self._tmp_to_use_node else tmp_node

    def visit_put(self, put):
        raise NotImplementedError("visit_put")

    def visit_put_tmp(self, put_tmp):
        def_name = put_tmp.get_def()
        use_expr = put_tmp.get_use()

        def_value = RegValue(def_name, None, ValueKind.Unknown, loc=self._current_loc)

        use_node = self.get_tmp_node(use_expr.get_name(), use_expr)
        use_node = self.get_tmp_to_use(use_node)
        def_node = VarNode(def_value, 1)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.Assign, stmt=put_tmp)
        self.ir_graph.add_edge(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]

    def visit_put_const(self, put_const):
        def_name = put_const.get_def()
        use_expr = put_const.get_use()
        use_cons = use_expr.get_name()
        def_value = RegValue(def_name, None, ValueKind.Unknown, loc=self._current_loc)
        use_value = ConsValue(use_cons, None, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        use_node = VarNode(use_value, 0)
        def_node = VarNode(def_value, 1)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.Assign, stmt=put_const)
        self.ir_graph.add_edge(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]

    def visit_imark(self, imark):
        # self.set_current_stmt_addr(imark.addr)
        return []
     
    def visit_puti(self, puti):
        raise NotImplementedError("visit_puti")

    def visit_wr_tmp(self, wr_tmp):
        def_name = wr_tmp.get_def()
        use_expr = wr_tmp.get_use()

        use_node = self.get_tmp_node(use_expr.get_name(), use_expr)
        def_node = self.get_tmp_node(def_name)

        use_node = self.get_tmp_to_use(use_node)
        self.add_tmp_to_use(def_node, use_node)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.Assign, stmt=wr_tmp)
        self.ir_graph.add_edge(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]
        
    def visit_wr_get(self, wr_get):
        def_name = wr_get.get_def()
        use_expr = wr_get.get_use()
        use_name = use_expr.get_name()
        
        size = use_expr.get_size()
        use_value = RegValue(use_name, size, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        use_node = VarNode(use_value, 0)
        def_node = self.get_tmp_node(def_name, size=size)

        self.add_tmp_to_use(def_node, use_node)
        
        edge = AssignEdge(use_node, def_node, kind=EdgeKind.Assign, stmt=wr_get)
        self.ir_graph.add_edge(edge)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]
        
    def visit_wr_binop(self, wr_binop):
        """
        处理 wr_binop 语句
        e.g., t41 = Sub32(t0,0x00000018)
        """
        def_name = wr_binop.get_def()
        use_expr = wr_binop.get_use()

        size = use_expr.get_size()

        args_node = use_expr.accept(self)
        args_value = [arg_node.var for arg_node in args_node]

        use_value = BinopValue(use_expr.op, args_value, size, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)
        use_node = VarNode(use_value, 0)
        def_node = self.get_tmp_node(def_name, size=size)

        self.add_tmp_to_use(def_node, use_node)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.BinopAssign, stmt=wr_binop)
        self.ir_graph.add_edge(edge)

        # Add op edge between use_node and args_node
        for idx, arg_node in enumerate(args_node):
            op_edge = OpEdge(arg_node, use_node, kind=EdgeKind.Binop, op_idx=idx)
            self.ir_graph.add_edge(op_edge)
            self.ir_graph.add_node(arg_node.id, arg_node)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]
        
    def visit_wr_load(self, wr_load):
        raise NotImplementedError("visit_wr_load")
    
    def visit_wr_load_cons(self, wr_load_cons):
        """
        处理 wr_load_cons 语句, 其中load的addr是常量
        e.g., t6 = LDle:I32(0x000173f0)
        """
        def_name = wr_load_cons.get_def()
        use_expr = wr_load_cons.get_use()
        use_name = use_expr.addr.get_name()
        size = use_expr.get_size()

        addr_value = ConsValue(use_name, None, ValueKind.GlobalPtr, expr=use_expr.addr, loc=self._current_loc)
        addr_node = VarNode(addr_value, 0)
        use_value = MemValue(addr_value, size, ValueKind.MemAccess, "load", expr=use_expr, loc=self._current_loc)

        use_node = VarNode(use_value, 0)
        def_node = self.get_tmp_node(def_name, size=size)

        self.add_tmp_to_use(def_node, use_node)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.LoadAssign, stmt=wr_load_cons)
        self.ir_graph.add_edge(edge)

        addr_edge = AddrEdge(addr_node, use_node, kind=EdgeKind.Addr)
        self.ir_graph.add_edge(addr_edge)
        self.ir_graph.add_node(addr_node.id, addr_node)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]

    def visit_wr_load_tmp(self, wr_load_tmp):
        """
        处理 wr_load_tmp 语句, 其中load的addr是临时变量
        e.g., t6 = LDle:I32(t0)
        """
        def_name = wr_load_tmp.get_def()
        use_expr = wr_load_tmp.get_use()
        use_name = use_expr.addr.get_name()
        size = use_expr.get_size()
        
        addr_node = self.get_tmp_node(use_name, rd_tmp=use_expr.addr, kind=ValueKind.Pointer)
        use_value = MemValue(addr_node.var, size, ValueKind.MemAccess, "load", expr=use_expr, loc=self._current_loc)

        use_node = VarNode(use_value, 0)
        def_node = self.get_tmp_node(def_name, size=size)

        self.add_tmp_to_use(def_node, use_node)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.LoadAssign, stmt=wr_load_tmp)
        self.ir_graph.add_edge(edge)

        addr_edge = AddrEdge(addr_node, use_node, kind=EdgeKind.Addr)
        self.ir_graph.add_edge(addr_edge)
        self.ir_graph.add_node(addr_node.id, addr_node)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]
        
    def visit_wr_ite(self, wr_ite):
        """
        处理 wr_ite 语句
        e.g., t42 = ITE(t41,t40,t39)
        """
        def_name = wr_ite.get_def()
        use_expr = wr_ite.get_use()
        guard_expr = use_expr.get_cond()
        iftrue_expr = use_expr.get_iftrue()
        iffalse_expr = use_expr.get_iffalse()
        
        try:
            guard_name = guard_expr.get_name()
            use_name_iftrue = iftrue_expr.get_name()
            use_name_iffalse = iffalse_expr.get_name()  
        except:
            raise l.error("Some error occurred when processing the wr_ite statement %s.", wr_ite)
        
        if isinstance(guard_name, str):
            guard_node = self.get_tmp_node(guard_name, rd_tmp=guard_expr, kind=ValueKind.Condition)
            
        elif isinstance(guard_name, int):
            guard_value = ConsValue(guard_name, None, ValueKind.Condition, expr=guard_expr, loc=self._current_loc)
            guard_node = VarNode(guard_value, 0)
        else:
            raise l.error("The guard of the wr_ite statement %s is not a temporary or a constant.", wr_ite)
         
        if isinstance(use_name_iftrue, str):
            use_node_iftrue = self.get_tmp_node(use_name_iftrue, rd_tmp=iftrue_expr)
            use_node_iftrue = self.get_tmp_to_use(use_node_iftrue)
            
        elif isinstance(use_name_iftrue, int):
            use_value_iftrue = ConsValue(use_name_iftrue, None, ValueKind.Unknown, expr=iftrue_expr, loc=self._current_loc)
            use_node_iftrue = VarNode(use_value_iftrue, 0)
        else:
            raise l.error("The alt of the wr_ite statement %s is not a temporary or a constant.", wr_ite)
        
        if isinstance(use_name_iffalse, str):
            use_node_iffalse = self.get_tmp_node(use_name_iffalse, rd_tmp=iffalse_expr)
            use_node_iffalse = self.get_tmp_to_use(use_node_iffalse)

        elif isinstance(use_name_iffalse, int):
            use_value_iffalse = ConsValue(use_name_iffalse, None, ValueKind.Unknown, expr=iffalse_expr, loc=self._current_loc)
            use_node_iffalse = VarNode(use_value_iffalse, 0)
        else:
            raise l.error("The alt of the wr_ite statement %s is not a temporary or a constant.", wr_ite)
        
        def_node = self.get_tmp_node(def_name)
        
        edge_iftrue = AssignEdge(use_node_iftrue, def_node, kind=EdgeKind.AssignIfTrue, guard=guard_node, stmt=wr_ite)
        self.ir_graph.add_edge(edge_iftrue)
        
        edge_iffalse = AssignEdge(use_node_iffalse, def_node, kind=EdgeKind.AssignIfFalse, guard=guard_node, stmt=wr_ite)
        self.ir_graph.add_edge(edge_iffalse)
        
        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node_iftrue.id, use_node_iftrue)
        self.ir_graph.add_node(use_node_iffalse.id, use_node_iffalse)
        self.ir_graph.add_node(guard_node.id, guard_node)

        return [edge_iftrue, edge_iffalse]
        
    def visit_wr_unop(self, wr_unop):
        """
        处理 wr_unop 语句
        e.g., t43 = 1to32(t42)
        """
        def_name = wr_unop.get_def()
        use_expr = wr_unop.get_use()
        size = use_expr.get_size()

        args_node = use_expr.accept(self)
        args_value = [arg_node.var for arg_node in args_node]
        use_value = UnopValue(use_expr.op, args_value, size, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        use_node = VarNode(use_value, 0)
        def_node = self.get_tmp_node(def_name, size=size)

        self.add_tmp_to_use(def_node, use_node)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.BinopAssign, stmt=wr_unop)
        self.ir_graph.add_edge(edge)

        for idx, arg_node in enumerate(args_node):
            op_edge = OpEdge(arg_node, use_node, kind=EdgeKind.Unaryop, op_idx=idx)
            self.ir_graph.add_edge(op_edge)
            self.ir_graph.add_node(arg_node.id, arg_node)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]

    def visit_loadg(self, loadg):
        """
        处理 loadg 语句
        e.g., t44 = LDle:I32(t43) if t42 else t41
        """
        guard_expr = loadg.get_guard()
        def_name = loadg.get_def()
        use_expr_in_guard = loadg.get_use_with_guard()
        use_expr_no_guard = loadg.get_use_without_guard()

        try:
            guard_name = guard_expr.get_name()
            use_name_in_guard = use_expr_in_guard.get_name()
            use_name_no_guard = use_expr_no_guard.get_name()
        except:
            raise l.error("Some error occurred when processing the loadg statement %s.", loadg)
        
        if isinstance(guard_name, str):
            guard_node = self.get_tmp_node(guard_name, rd_tmp=guard_expr, kind=ValueKind.Condition)
        elif isinstance(guard_name, int):
            guard_value = ConsValue(guard_name, None, ValueKind.Condition, expr=guard_expr, loc=self._current_loc)
            guard_node = VarNode(guard_value, 0)
        else:
            raise l.error("The guard of the loadg statement %s is not a temporary or a constant.", loadg)
        
        if isinstance(use_name_in_guard, str):
            addr_node = self.get_tmp_node(use_name_in_guard, rd_tmp=use_expr_in_guard, kind=ValueKind.Pointer)
            addr_node = self.get_tmp_to_use(addr_node)
            addr_node.change_var_kind(ValueKind.Pointer)
            use_value_in_guard = MemValue(addr_node.var, None, ValueKind.MemAccess, "load", expr=use_expr_in_guard, loc=self._current_loc)
            use_node_in_guard = VarNode(use_value_in_guard, 0)
        elif isinstance(use_name_in_guard, int):
            addr_value = ConsValue(use_name_in_guard, None, ValueKind.Pointer, expr=use_expr_in_guard, loc=self._current_loc)
            addr_node = VarNode(addr_value, 0)
            use_value_in_guard = MemValue(addr_value, None, ValueKind.MemAccess, "load", expr=use_expr_in_guard, loc=self._current_loc)
            use_node_in_guard = VarNode(use_value_in_guard, 0)
        else:
            raise l.error("The use of the loadg statement %s is not a temporary or a constant.", loadg)

        if isinstance(use_name_no_guard, str):
            use_node_no_guard = self.get_tmp_node(use_name_no_guard, rd_tmp=use_expr_no_guard)
            use_node_no_guard = self.get_tmp_to_use(use_node_no_guard)
        
        elif isinstance(use_name_no_guard, int):
            use_value_no_guard = ConsValue(use_name_no_guard, None, ValueKind.Unknown, expr=use_expr_no_guard, loc=self._current_loc)
            use_node_no_guard = VarNode(use_value_no_guard, 0)
        else:
            raise l.error("The alt of the loadg statement %s is not a temporary or a constant.", loadg)
        
        def_node = self.get_tmp_node(def_name)
        
        edge_in_guard = AssignEdge(use_node_in_guard, def_node, kind=EdgeKind.LoadAssign, guard=guard_node, stmt=loadg)
        self.ir_graph.add_edge(edge_in_guard)
        
        edge_no_guard = AssignEdge(use_node_no_guard, def_node, kind=EdgeKind.AssignIfFalse, guard=guard_node, stmt=loadg)
        self.ir_graph.add_edge(edge_no_guard)

        addr_edge = AddrEdge(addr_node, use_node_in_guard, kind=EdgeKind.Addr)
        self.ir_graph.add_edge(addr_edge)
        self.ir_graph.add_node(addr_node.id, addr_node)
        
        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node_in_guard.id, use_node_in_guard)
        self.ir_graph.add_node(use_node_no_guard.id, use_node_no_guard)
        self.ir_graph.add_node(guard_node.id, guard_node)

        return [edge_in_guard, edge_no_guard]

    def visit_storeg(self, storeg):
        """
        处理 storeg 语句
        e.g., STle(t43) = t44 if t42
        """
        guard_expr = storeg.get_guard()
        def_expr = storeg.get_def()
        use_expr = storeg.get_use()

        try:
            guard_name = guard_expr.get_name()
            def_name = def_expr.get_name()
            use_name = use_expr.get_name()
        except:
            raise l.error("Some error occurred when processing the storeg statement %s.", storeg)
        
        if isinstance(guard_name, str):
            guard_node = self.get_tmp_node(guard_name, rd_tmp=guard_expr, kind=ValueKind.Condition)
            # guard_value = TmpValue(guard_name, None, ValueKind.Condition, expr=guard_expr, loc=self._current_loc)
        elif isinstance(guard_name, int):
            guard_value = ConsValue(guard_name, None, ValueKind.Condition, expr=guard_expr, loc=self._current_loc)
            guard_node = VarNode(guard_value, 0)
        else:
            raise l.error("The guard of the storeg statement %s is not a temporary or a constant.", storeg)
        
        if isinstance(use_name, str):
            use_node = self.get_tmp_node(use_name, rd_tmp=use_expr)
            use_node = self.get_tmp_to_use(use_node)
        elif isinstance(use_name, int):
            use_value = ConsValue(use_name, None, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)
            use_node = VarNode(use_value, 0)
        else:
            raise l.error("The use of the storeg statement %s is not a temporary or a constant.", storeg)
        
        if isinstance(def_name, str):
            addr_node = self.get_tmp_node(def_name, rd_tmp=def_expr, kind=ValueKind.Pointer)
            addr_node = self.get_tmp_to_use(addr_node)
            addr_node.change_var_kind(ValueKind.Pointer)
            def_value = MemValue(addr_node.var, None, ValueKind.MemAccess, "store", expr=def_expr, loc=self._current_loc)
            def_node = VarNode(def_value, 1)
        elif isinstance(def_name, int):
            addr_value = ConsValue(def_name, None, ValueKind.Pointer, expr=def_expr, loc=self._current_loc)
            addr_node = VarNode(addr_value, 0)
            def_value = MemValue(addr_node.var, None, ValueKind.MemAccess, "store", expr=def_expr, loc=self._current_loc)
            def_node = VarNode(def_value, 1)
        else:
            raise l.error("The def of the storeg statement %s is not a temporary or a constant.", storeg)
        
        edge = AssignEdge(use_node, def_node, kind=EdgeKind.StoreAssign, guard=guard_node, stmt=storeg)
        self.ir_graph.add_edge(edge)
        
        addr_edge = AddrEdge(addr_node, def_node, kind=EdgeKind.Addr)
        self.ir_graph.add_edge(addr_edge)
        self.ir_graph.add_node(addr_node.id, addr_node)
        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)
        self.ir_graph.add_node(guard_node.id, guard_node)

        return [edge]
    
    def visit_store(self, store):
        raise NotImplementedError("visit_store")

    def visit_reg_store_tmp(self, reg_store_tmp):
        """
        处理 reg_store_tmp 语句, 其中sotre的addr是临时变量，存储的是临时变量
        e.g., STle(t43) = t44
        """
        def_expr = reg_store_tmp.get_def()
        use_expr = reg_store_tmp.get_use()
        use_name = use_expr.get_name()
        def_name = def_expr.get_name()

        addr_node = self.get_tmp_node(def_name, rd_tmp=def_expr, kind=ValueKind.Pointer)
        addr_node = self.get_tmp_to_use(addr_node)
        addr_node.change_var_kind(ValueKind.Pointer)
        def_value = MemValue(addr_node.var, None, ValueKind.MemAccess, "store", expr=def_expr, loc=self._current_loc)

        use_node = self.get_tmp_node(use_name, rd_tmp=use_expr)
        use_node = self.get_tmp_to_use(use_node)
        def_node = VarNode(def_value, 1)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.StoreAssign, stmt=reg_store_tmp)
        self.ir_graph.add_edge(edge)

        addr_edge = AddrEdge(addr_node, def_node, kind=EdgeKind.Addr)
        self.ir_graph.add_edge(addr_edge)
        self.ir_graph.add_node(addr_node.id, addr_node)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]

    def visit_reg_store_cons(self, reg_store_cons):
        """
        处理 reg_store_cons 语句, 其中store的addr是临时变量，存储的是常量
        e.g., STle(t44) = 0x000173f0
        """
        def_expr = reg_store_cons.get_def()
        use_expr = reg_store_cons.get_use()
        use_cons = use_expr.get_name()
        def_name = def_expr.get_name()

        addr_node = self.get_tmp_node(def_name, rd_tmp=def_expr, kind=ValueKind.Pointer)
        addr_node = self.get_tmp_to_use(addr_node)
        addr_node.change_var_kind(ValueKind.Pointer)
        def_value = MemValue(addr_node.var, None, ValueKind.MemAccess, "store", expr=def_expr, loc=self._current_loc)
        use_value = ConsValue(use_cons, None, ValueKind.Unknown, expr=use_expr, loc=self._current_loc)

        use_node = VarNode(use_value, 0)
        def_node = VarNode(def_value, 1)

        edge = AssignEdge(use_node, def_node, kind=EdgeKind.StoreAssign, stmt=reg_store_cons)
        self.ir_graph.add_edge(edge)

        addr_edge = AddrEdge(addr_node, def_node, kind=EdgeKind.Addr)
        self.ir_graph.add_edge(addr_edge)
        self.ir_graph.add_node(addr_node.id, addr_node)

        self.ir_graph.add_node(def_node.id, def_node)
        self.ir_graph.add_node(use_node.id, use_node)

        return [edge]
        
    def visit_global_store_tmp(self, global_store_tmp):
        raise NotImplementedError("visit_global_store_tmp")

    def visit_global_store_cons(self, global_store_cons):
        raise NotImplementedError("visit_global_store_cons")
        
    def visit_exit(self, ext):
        if not isinstance(ext.guard, pyvex.expr.RdTmp):
            raise NotImplementedError("visit_exit")
        
        guard_name = ext.guard.get_name()
        target_addr = ext.dst.value
        size = ext.dst.size
        # guard_value = TmpValue(guard_name, None, ValueKind.Condition, expr=ext.guard, loc=self._current_loc)
        target_value = ConsValue(target_addr, size, ValueKind.CodePtr, expr=ext.dst, loc=self._current_loc)

        if ext.jk != "Ijk_Boring":
            raise l.warning("The exit statement %s is not a boring exit.", ext)

        guard_node = self.get_tmp_node(guard_name, rd_tmp=ext.guard, kind=ValueKind.Condition)
        target_node = VarNode(target_value, 0)

        edge = FlowEdge(guard_node, target_node, kind=EdgeKind.Jump, guard=guard_node, stmt=ext)
        self.ir_graph.add_edge(edge)

        self.ir_graph.add_node(guard_node.id, guard_node)
        self.ir_graph.add_node(target_node.id, target_node)

        return [edge]

    # Expressions visitors
    def visit_binop(self, binop):
        args_node = []
        size = binop.get_size()
        for arg in binop.args:
            try:
                node = arg.accept(self)
                node.set_size(size)
                args_node.append(node)
            except:
                raise l.error("The argument %s of the binop statement %s is not a temporary or a constant.", arg, binop)
        return args_node
    
    def visit_unop(self, unop):
        args_node = []
        size = unop.get_size()
        for arg in unop.args:
            try:
                node = arg.accept(self)
                node.set_size(size)
                args_node.append(node)
            except:
                raise l.error("The argument %s of the unop statement %s is not a temporary or a constant.", arg, unop)
        return args_node

    def visit_rdtmp(self, rdtmp):
        return self.get_tmp_node(rdtmp.get_name(), rd_tmp=rdtmp, kind=ValueKind.Unknown)
    
    def visit_const(self, const):
        return VarNode(ConsValue(const.get_name(), None, ValueKind.Const, expr=const, loc=self._current_loc), 0)
        