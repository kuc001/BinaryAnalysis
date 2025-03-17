from pyvex.stmt import IRStmt
from pyvex.expr import IRExpr

class IRVisitor:
    """访问者模式基类,用于遍历IR表达式和语句"""
    
    # Expression visitors
    def visit_binop(self, expr: IRExpr):
        """访问Binop表达式"""
        raise NotImplementedError()
    
    def visit_const(self, expr: IRExpr):
        """访问Const表达式"""
        raise NotImplementedError()
        
    def visit_get(self, expr: IRExpr):
        """访问Get表达式"""
        raise NotImplementedError()
    
    def visit_load(self, expr: IRExpr):
        """访问Load表达式"""
        raise NotImplementedError()
        
    def visit_rdtmp(self, expr: IRExpr):
        """访问RdTmp表达式"""
        raise NotImplementedError()
        
    def visit_binder(self, expr: IRExpr):
        """访问Binder表达式"""
        raise NotImplementedError()
    
    def visit_ccall(self, expr: IRExpr):
        """访问CCall表达式"""
        raise NotImplementedError()
        
    def visit_geti(self, expr: IRExpr):
        """访问GetI表达式"""
        raise NotImplementedError()
        
    def visit_ite(self, expr: IRExpr):
        """访问ITE表达式"""
        raise NotImplementedError()
        
    def visit_qop(self, expr: IRExpr):
        """访问Qop表达式"""
        raise NotImplementedError()
        
    def visit_triop(self, expr: IRExpr):
        """访问Triop表达式"""
        raise NotImplementedError()
        
    def visit_unop(self, expr: IRExpr):
        """访问Unop表达式"""
        raise NotImplementedError()
        
    def visit_vecret(self, expr: IRExpr):
        """访问Vector表达式"""
        raise NotImplementedError()
    
    def visit_gsptr(self, expr: IRExpr):
        """访问GsPtr表达式"""
        raise NotImplementedError()
    
    
    
    # Statement visitors
    def visit_abi_hint(self, stmt: IRStmt):
        """访问AbiHint语句"""
        raise NotImplementedError()
        
    def visit_cas(self, stmt: IRStmt):
        """访问CAS语句"""
        raise NotImplementedError()
        
    def visit_dirty(self, stmt: IRStmt):
        """访问Dirty语句"""
        raise NotImplementedError()
        
    def visit_exit(self, stmt: IRStmt):
        """访问Exit语句"""
        raise NotImplementedError()
        
    def visit_imark(self, stmt: IRStmt):
        """访问IMark语句"""
        raise NotImplementedError()
        
    def visit_llsc(self, stmt: IRStmt):
        """访问LLSC语句"""
        raise NotImplementedError()
        
    def visit_loadg(self, stmt: IRStmt):
        """访问LoadG语句"""
        raise NotImplementedError()
        
    def visit_mbe(self, stmt: IRStmt):
        """访问MBE语句"""
        raise NotImplementedError()
        
    def visit_put(self, stmt: IRStmt):
        """访问Put语句"""
        raise NotImplementedError()
        
    def visit_puti(self, stmt: IRStmt):
        """访问PutI语句"""
        raise NotImplementedError()
        
    def visit_store(self, stmt: IRStmt):
        """访问Store语句"""
        raise NotImplementedError()
        
    def visit_storeg(self, stmt: IRStmt):
        """访问StoreG语句"""
        raise NotImplementedError()
        
    def visit_wrtmp(self, stmt: IRStmt):
        """访问WrTmp语句"""
        raise NotImplementedError()
