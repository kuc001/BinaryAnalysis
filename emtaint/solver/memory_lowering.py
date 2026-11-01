"""P5 local byte-definition/ITE lowering through the existing pure-BV port.

No whole-program SMT heap and no raw Claripy Load/Store. May-alias predicates
are over-approximations; SAT is a candidate, never a proof of concrete alias.
"""
from emtaint.core.contracts import TypeKind, Assessment
from emtaint.memory.state import SymbolicOp
from emtaint.memory.engine import PythonMemoryEngine, combine, token, over
from emtaint.memory.policies import BudgetExceeded
from .port import Term, SolverQuery, UnsupportedQuery, SolverResult, SolverStatus
from .lowering import LoweringRequest, LoweringResult, LoweringStatus


class MemorySolverLowering:
    def __init__(self):
        self.solver_queries = 0
        self.last_lowering = None

    def solve(self, request, port):
        lowered = self.lower(request)
        self.last_lowering = lowered
        if lowered.status != LoweringStatus.READY:
            status = SolverStatus.UNSUPPORTED if lowered.status == LoweringStatus.UNSUPPORTED else SolverStatus.UNKNOWN
            return SolverResult(status,reason='Lowering '+lowered.status.value,
                                origin=lowered.formula_origins[0])
        limit = min(request.snapshot.budgets.solver_queries,request.budget.max_solver_queries)
        if self.solver_queries >= limit:
            return SolverResult(SolverStatus.UNKNOWN,reason='Solver query budget exhausted; incomplete',
                                origin=lowered.formula_origins[0])
        self.solver_queries += 1
        # Backend status and crash/timeout remain explicit. Inspect last_lowering
        # for precision/model assumptions before interpreting SAT as a witness.
        return port.solve(lowered.query)

    def lower(self, request):
        if not isinstance(request,LoweringRequest):
            raise TypeError('Only typed LoweringRequest accepted; no raw legacy memory markers')
        origins = tuple(o.id for o in request.snapshot.origin_map)
        try:
            engine = PythonMemoryEngine.from_snapshot(request.snapshot)
            root,resolver = engine.resolve(request.expression,request.budget)
            guards = []
            assessments = [request.snapshot.assessment] + resolver.assessments
            for guard in request.guards:
                lowered,r = engine.resolve(guard,request.budget)
                guards.append(lowered); assessments.extend(r.assessments)
            terms = self.export(engine,(root,*guards),request.budget.max_steps)
            constraints = tuple(terms[g] for g in guards)
            if request.operation == 'check':
                constraints += (terms[root],)
                expression = None
            else:
                expression = terms[root]
            query = SolverQuery(constraints or (Term('BoolV',None,(True,)),),expression,
                request.operation,request.budget.timeout_ms,request.limit,origins[0])
            query.validate()
            return LoweringResult(LoweringStatus.READY,query,origins,combine(assessments))
        except BudgetExceeded as error:
            return LoweringResult(LoweringStatus.INCOMPLETE,None,origins,error.assessment)
        except UnsupportedQuery as error:
            return LoweringResult(LoweringStatus.UNSUPPORTED,None,origins,
                Assessment(unsupported_ops=('MemorySolverLowering',),diagnostics=(str(error),)))
        except (ValueError,KeyError) as error:
            return LoweringResult(LoweringStatus.UNSUPPORTED,None,origins,
                Assessment(unsupported_ops=('MemorySolverLowering',),diagnostics=(str(error),)))

    def export(self, engine, roots, max_steps):
        done,stack,steps = {},[(ref,False) for ref in roots],0
        binary = {SymbolicOp.ADD:'Add',SymbolicOp.SUB:'Sub',SymbolicOp.MUL:'Mul',
            SymbolicOp.AND:'AndBits',SymbolicOp.OR:'OrBits',SymbolicOp.XOR:'XorBits',
            SymbolicOp.EQ:'Eq',SymbolicOp.ULT:'ULT',SymbolicOp.SLT:'SLT'}
        while stack:
            ref,ready = stack.pop()
            if ref in done: continue
            steps += 1
            if steps > max_steps: raise BudgetExceeded('worklist_iterations',max_steps,steps)
            n = engine.dag.nodes[ref]
            if not ready and n.operands:
                stack.append((ref,True));stack.extend((x,False) for x in n.operands if x not in done)
                continue
            width = None if n.type.kind == TypeKind.BOOL else n.type.bits
            args = tuple(done[x] for x in n.operands)
            if n.op == SymbolicOp.CONSTANT:
                term = Term('BoolV' if width is None else 'BVV',width,(n.value,))
            elif n.op == SymbolicOp.SYMBOL:
                name = 'p5-'+token((engine.scope,n.type,n.value))
                term = Term('BVS',width or 1,(name,))
                if width is None: term = Term('Eq',None,(term,Term('BVV',1,(1,))))
            elif n.op == SymbolicOp.COPY: term = args[0]
            elif n.op in binary: term = Term(binary[n.op],width,args)
            elif n.op == SymbolicOp.IF: term = Term('If',width,args)
            elif n.op == SymbolicOp.NOT:
                term = (Term('Not',None,args) if width is None else
                        Term('XorBits',width,(args[0],Term('BVV',width,((1 << width)-1,)))))
            elif n.op == SymbolicOp.CONCAT: term = Term('Concat',width,args)
            elif n.op == SymbolicOp.EXTRACT: term = Term('Extract',width,(*n.params,args[0]))
            elif n.op in (SymbolicOp.ZERO_EXTEND,SymbolicOp.SIGN_EXTEND):
                term = Term('ZeroExt' if n.op == SymbolicOp.ZERO_EXTEND else 'SignExt',width,(*n.params,args[0]))
            else: raise UnsupportedQuery('Unlowered symbolic operation: '+n.op.value)
            done[ref] = term
        return done
