"""Explicit native Claripy boundary. Memory effects remain unsupported until P5."""
from emtaint.compat.legacy_memory import describe_marker
from emtaint.solver.port import (SolverQuery, SolverResult, SolverStatus, Term, UnsupportedQuery)
from . import ast_tools


def load_claripy():
    import importlib.metadata
    from pathlib import Path
    import sys
    expected = Path(__file__).resolve().parents[3] / ".venv"
    if Path(sys.prefix).resolve() != expected.resolve():
        raise RuntimeError("Use the target .venv interpreter")
    for package in ("angr", "claripy", "cle", "pyvex", "archinfo"):
        if importlib.metadata.version(package) != "9.3.4":
            raise RuntimeError("This adapter is validated only for target " + package + " 9.3.4")
    import claripy
    Path(claripy.__file__).resolve().relative_to(expected.resolve())
    return claripy


def native_status(solver):
    # Pinned 9.3.4 backend_z3.z3_solver_sat raises on UNKNOWN; False is UNSAT.
    # This is deliberately not enabled for arbitrary injected modules.
    return "SAT" if solver.satisfiable() else "UNSAT"


def exception_status(module, error):
    seen = set()
    while error is not None and id(error) not in seen:
        seen.add(id(error))
        errors = getattr(module, "errors", None)
        interrupt = getattr(errors, "ClaripySolverInterruptError", ())
        z3_error = getattr(errors, "ClaripyZ3Error", ())
        if interrupt and isinstance(error, interrupt):
            return SolverStatus.TIMEOUT if "timeout" in str(error).lower() else SolverStatus.UNKNOWN
        if z3_error and isinstance(error, z3_error) and str(error).lower().startswith("solver unknown:"):
            return SolverStatus.UNKNOWN
        error = error.__cause__ or error.__context__
    return SolverStatus.ERROR


class ClaripyAdapter:
    def __init__(self, module=None, exact_status_reader=None):
        self.c = module if module is not None else load_claripy()
        # Presence of check_satisfiability() is insufficient: the old base
        # implementation folds UNKNOWN into UNSAT. A reader needs its own proof.
        self.exact_status_reader = (native_status if module is None and exact_status_reader is None
                                    else exact_status_reader)

    def children(self, root, unique=False, max_visits=10000):
        return ast_tools.children(self.c, root, unique, max_visits)

    def leaves(self, root):
        return ast_tools.leaves(self.c, root)

    def structural_key(self, root):
        return ast_tools.structural_key(self.c, root)

    def replace(self, root, old, new):
        return ast_tools.replace(self.c, root, old, new)

    def simplify(self, root):
        return self.c.simplify(root)

    def export(self, root):
        value = Term.from_dict(ast_tools.export(self.c, root))
        from emtaint.solver.port import validate_term
        validate_term(value)
        return value

    def extract_legacy_marker(self, root):
        if root.op not in ("Load", "Store") or len(root.args) != 1:
            raise ValueError("Not a recognized local legacy memory marker")
        address = Term.from_dict(ast_tools.export(self.c, root.args[0], allow_legacy_memory=True))
        return describe_marker(root.op, address, root.size())

    def _lower_pure_bv(self, term):
        c = self.c
        args = [self._lower_pure_bv(a) if isinstance(a, Term) else a for a in term.args]
        if term.op == "BVS":
            return c.BVS(args[0], term.width, explicit_name=True)
        if term.op == "BVV":
            return c.BVV(args[0], term.width)
        if term.op == "BoolV":
            return c.BoolV(args[0])
        binary = {"Add": lambda a, b: a + b, "Sub": lambda a, b: a - b,
                  "Mul": lambda a, b: a * b, "AndBits": lambda a, b: a & b,
                  "OrBits": lambda a, b: a | b, "XorBits": lambda a, b: a ^ b,
                  "Eq": lambda a, b: a == b}
        if term.op in binary:
            return binary[term.op](*args)
        return getattr(c, term.op)(*args)

    def solve(self, query: SolverQuery) -> SolverResult:
        try:
            query.validate()
            constraints = [self._lower_pure_bv(c) for c in query.constraints]
            solver = self.c.Solver(timeout=query.timeout_ms)
            solver.add(constraints)
            if self.exact_status_reader is not None:
                raw = self.exact_status_reader(solver)
                status = {"SAT": SolverStatus.SAT, "UNSAT": SolverStatus.UNSAT,
                          "UNKNOWN": SolverStatus.UNKNOWN}.get(str(raw).upper(), SolverStatus.UNKNOWN)
                reason = str(raw)
            else:
                sat = solver.satisfiable()
                # A boolean-only API cannot prove False wasn't a collapsed UNKNOWN.
                status = SolverStatus.SAT if sat is True else SolverStatus.UNKNOWN
                reason = "boolean SAT" if sat is True else "Boolean False lacks a verified UNSAT/UNKNOWN discriminator"
            values = ()
            if status == SolverStatus.SAT and query.operation != "check":
                expression = self._lower_pure_bv(query.expression)
                if query.operation == "eval":
                    values = tuple(solver.eval(expression, query.limit))
                else:
                    values = (getattr(solver, query.operation)(expression),)
            return SolverResult(status, values, reason, origin=query.origin)
        except (UnsupportedQuery, ast_tools.UnsupportedAST) as error:
            return SolverResult(SolverStatus.UNSUPPORTED, reason=str(error), origin=query.origin)
        except Exception as error:
            status = exception_status(self.c, error)
            return SolverResult(status, reason=type(error).__name__ + ": " + str(error), origin=query.origin)
