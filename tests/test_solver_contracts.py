import ast
from pathlib import Path
import sys
import types
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))
from emtaint.compat.legacy_memory import describe_marker
from emtaint.solver.port import SolverQuery, SolverResult, SolverStatus, Term, UnsupportedQuery, validate_term
from emtaint.solver.backends import ast_tools
from emtaint.solver.backends.claripy_adapter import ClaripyAdapter
from p1_runtime import ProbeWriteGuard
from emtaint.solver.process_port import SubprocessSolverPort


def symbol(name="x", width=32):
    return Term("BVS", width, (name,))


def const(value=7, width=32):
    return Term("BVV", width, (value,))


def equals(a, b):
    return Term("Eq", None, (a, b))


class ProtocolTests(unittest.TestCase):
    def test_round_trip_query(self):
        q = SolverQuery((equals(symbol(), const()),), symbol(), "eval", origin="fixture:1")
        self.assertEqual(SolverQuery.from_dict(q.to_dict()), q)

    def test_memory_anywhere_is_unsupported(self):
        for op in ("Load", "Store", "MemoryRead", "Select", "ArrayStore"):
            with self.subTest(op=op), self.assertRaises(UnsupportedQuery):
                SolverQuery((equals(Term(op, 32, (symbol(),)), const()),)).validate()

    def test_invalid_width_and_sort_are_errors(self):
        for term in (const(True), const(256, 8), const(-1), symbol(width=True),
                     Term("Add", 32, (symbol(), const(1, 16))),
                     Term("Eq", None, (symbol(), Term("BoolV", None, (True,))))):
            with self.subTest(term=term), self.assertRaises(ValueError):
                validate_term(term)

    def test_conflicting_symbol_width_across_expressions(self):
        with self.assertRaises(ValueError):
            SolverQuery((equals(symbol(), const()),), symbol(width=16), "eval").validate()

    def test_bounds_extension_and_boolean_conditions(self):
        for term in (Term("Extract", 8, (31, 24, symbol())),
                     Term("ZeroExt", 40, (8, symbol())),
                     Term("SignExt", 40, (8, symbol())),
                     Term("If", 32, (equals(symbol(), const()), symbol(), const()))):
            validate_term(term)
        with self.assertRaises(ValueError):
            validate_term(Term("Extract", 8, (40, 33, symbol())))

    def test_unknown_operation_fails_closed(self):
        with self.assertRaises(UnsupportedQuery):
            validate_term(Term("Guess", 32, (symbol(),)))

    def test_mutable_arguments_are_rejected(self):
        with self.assertRaises(ValueError):
            validate_term(Term("BVS", 32, ["x"]))
        with self.assertRaises(ValueError):
            SolverQuery([Term("BoolV", None, (True,))]).validate()

    def test_export_budget(self):
        expression = symbol()
        for _ in range(70):
            expression = Term("Add", 32, (expression, const()))
        with self.assertRaises(UnsupportedQuery):
            validate_term(expression)

    def test_flat_batch_does_not_consume_linear_depth(self):
        constraints = tuple(equals(symbol('x' + str(i)), const()) for i in range(528))
        q = SolverQuery(constraints)
        self.assertEqual(SolverQuery.from_dict(q.to_dict()).constraints, constraints)
        with self.assertRaises(ValueError):
            SolverQuery(constraints + (equals(symbol('x0', 16), const(7, 16)),)).validate()

    def test_explicit_status_never_coerces_to_boolean(self):
        for status in SolverStatus:
            value = SolverResult(status, reason="test", origin="fixture")
            with self.assertRaises(TypeError):
                bool(value)
            self.assertEqual(SolverResult.from_dict(value.to_dict()), value)

    def test_marker_does_not_invent_memory_effects(self):
        marker = describe_marker("Store", symbol("pointer"), 16)
        self.assertEqual((marker.address_bits, marker.value_bits), (32, 16))
        self.assertIn("stored_value", marker.missing_semantics)
        self.assertIn("memory_version", marker.missing_semantics)
        with self.assertRaises(UnsupportedQuery):
            validate_term(Term(marker.kind, marker.value_bits, (marker.address,)))

    def test_null_device_exception_is_narrow(self):
        from legacy_readonly_bootstrap import ForbiddenMutation
        guard = ProbeWriteGuard([])
        if sys.platform == "win32":
            guard.check(r"\\.\NUL", "os.open")
        with self.assertRaises(ForbiddenMutation):
            guard.check(ROOT / "not-allowed.log", "os.open")
        with self.assertRaises(ForbiddenMutation):
            guard.check(r"\\.\NUL", "os.utime")

    def test_public_solver_and_compat_modules_have_no_native_import(self):
        for relative in ("emtaint/solver/port.py", "emtaint/compat/legacy_memory.py"):
            tree = ast.parse((ROOT / relative).read_text())
            modules = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    modules.extend(n.name for n in node.names)
                elif isinstance(node, ast.ImportFrom):
                    modules.append(node.module or "")
            self.assertFalse(any(m.split(".")[0] in ("angr", "claripy", "pyvex", "idaapi") for m in modules))


class AdapterStatusTests(unittest.TestCase):
    """Fault injection verifies classification, not real solver timeout capability."""
    def fake(self, raw=None, error=None, boolean=False):
        class FakeSolver:
            def __init__(self, timeout):
                self.timeout = timeout
            def add(self, constraints):
                pass
            def check_satisfiability(self):
                if error:
                    raise error
                return raw
        if boolean:
            del FakeSolver.check_satisfiability
            FakeSolver.satisfiable = lambda self: False
        module = types.SimpleNamespace(Solver=FakeSolver, BoolV=lambda v: v,
                                       errors=types.SimpleNamespace())
        return ClaripyAdapter(module, exact_status_reader=None if boolean else lambda solver: solver.check_satisfiability())

    def test_three_way_status(self):
        q = SolverQuery((Term("BoolV", None, (True,)),))
        for raw, want in (("SAT", SolverStatus.SAT), ("UNSAT", SolverStatus.UNSAT),
                          ("UNKNOWN", SolverStatus.UNKNOWN), ("unexpected", SolverStatus.UNKNOWN)):
            self.assertEqual(self.fake(raw).solve(q).status, want)

    def test_false_without_discriminator_is_unknown(self):
        q = SolverQuery((Term("BoolV", None, (True,)),))
        self.assertEqual(self.fake(boolean=True).solve(q).status, SolverStatus.UNKNOWN)

    def test_named_three_way_method_is_not_trusted_without_proof(self):
        adapter = self.fake(boolean=True)
        adapter.c.Solver.check_satisfiability = lambda self: "UNSAT"
        q = SolverQuery((Term("BoolV", None, (True,)),))
        self.assertEqual(adapter.solve(q).status, SolverStatus.UNKNOWN)

    def test_backend_error_is_not_unsat(self):
        q = SolverQuery((Term("BoolV", None, (True,)),))
        self.assertEqual(self.fake(error=RuntimeError("failure")).solve(q).status, SolverStatus.ERROR)

    def test_interrupt_and_timeout_are_distinct(self):
        class Interrupt(Exception):
            pass
        q = SolverQuery((Term("BoolV", None, (True,)),))
        for message, want in (("timeout", SolverStatus.TIMEOUT), ("canceled", SolverStatus.UNKNOWN)):
            adapter = self.fake(error=Interrupt(message))
            adapter.c.errors.ClaripySolverInterruptError = Interrupt
            self.assertEqual(adapter.solve(q).status, want)

    def test_wrapped_backend_unknown_is_not_error_or_unsat(self):
        class Z3Error(Exception):
            pass
        class Interrupt(Exception):
            pass
        q = SolverQuery((Term('BoolV', None, (True,)),))
        for inner, want in ((Z3Error('solver unknown: incomplete'), SolverStatus.UNKNOWN),
                            (Z3Error('other failure'), SolverStatus.ERROR),
                            (Interrupt('timeout'), SolverStatus.TIMEOUT)):
            outer = RuntimeError('frontend wrapper')
            outer.__cause__ = inner
            adapter = self.fake(error=outer)
            adapter.c.errors.ClaripyZ3Error = Z3Error
            adapter.c.errors.ClaripySolverInterruptError = Interrupt
            self.assertEqual(adapter.solve(q).status, want)

    def test_owned_loader_enables_verified_reader_only(self):
        fake = self.fake(boolean=True).c
        q = SolverQuery((Term('BoolV', None, (True,)),))
        with mock.patch('emtaint.solver.backends.claripy_adapter.load_claripy', return_value=fake):
            self.assertEqual(ClaripyAdapter().solve(q).status, SolverStatus.UNSAT)
        self.assertEqual(ClaripyAdapter(fake).solve(q).status, SolverStatus.UNKNOWN)


class ASTToolsTests(unittest.TestCase):
    """Small AST double tests topology, budgets and rejection independently of native code."""
    def setUp(self):
        class Base:
            pass
        class BV(Base):
            def __init__(self, op, args, width=32, annotations=()):
                self.op, self.args, self.width, self.annotations = op, tuple(args), width, annotations
            def size(self):
                return self.width
        self.BV = BV
        self.c = types.SimpleNamespace(ast=types.SimpleNamespace(Base=Base, BV=BV))
        self.x = BV("BVS", ("x", None, None, None, False, False, None))

    def test_legacy_and_target_bvs_export_same_key(self):
        target_x = self.BV("BVS", ("x", 32))
        self.assertEqual(ast_tools.structural_key(self.c, self.x), ast_tools.structural_key(self.c, target_x))
        self.assertNotEqual(ast_tools.structural_key(self.c, self.x), ast_tools.structural_key(self.c, self.BV("BVS", ("x", 16), 16)))

    def test_shared_occurrences_and_unique_nodes_are_distinct(self):
        root = self.BV("Concat", (self.x, self.x), 64)
        self.assertEqual(list(ast_tools.children(self.c, root)), [self.x, self.x])
        self.assertEqual(list(ast_tools.children(self.c, root, unique=True)), [self.x])
        self.assertEqual(list(ast_tools.leaves(self.c, root)), [self.x])

    def test_preorder_and_legacy_leaf_order_with_distinct_branches(self):
        y = self.BV("BVS", ("y", 32))
        k = self.BV("BVV", (7, 32))
        left = self.BV("__add__", (self.x, k))
        right = self.BV("__sub__", (y, k))
        root = self.BV("Concat", (left, right), 64)
        self.assertEqual(list(ast_tools.children(self.c, root)), [left, self.x, k, right, y, k])
        self.assertEqual(list(ast_tools.leaves(self.c, root)), [k, y, self.x])

    def test_annotation_vsa_and_memory_do_not_silently_disappear(self):
        for node in (self.BV("BVS", ("x", 32), annotations=(object(),)),
                     self.BV("BVS", ("x", 1, 5, 2, False, False, None)),
                     self.BV("BVS", ("x", 0, None, None, False, False, None)),
                     self.BV("Load", (self.x,)), self.BV("Store", (self.x,))):
            with self.subTest(op=node.op), self.assertRaises(ast_tools.UnsupportedAST):
                ast_tools.export(self.c, node)

    def test_nested_memory_is_only_described(self):
        node = self.BV("Load", (self.BV("Store", (self.x,)),), 16)
        data = ast_tools.export(self.c, node, allow_legacy_memory=True)
        self.assertEqual(data["args"][0]["op"], "Store")
        adapter = ClaripyAdapter(self.c)
        marker = adapter.extract_legacy_marker(node)
        self.assertEqual(marker.value_bits, 16)
        self.assertEqual(marker.address.op, "Store")
        with self.assertRaises(UnsupportedQuery):
            validate_term(marker.address)

    def test_traversal_budget_is_explicit(self):
        root = self.BV("Concat", (self.x, self.x), 64)
        with self.assertRaises(ast_tools.UnsupportedAST):
            list(ast_tools.children(self.c, root, max_visits=1))

    def test_module_replace_fallback_preserves_sort_check(self):
        replacement = self.BV('BVS', ('y', 32))
        self.c.replace = mock.Mock(return_value=replacement)
        self.assertIs(ast_tools.replace(self.c, self.x, self.x, replacement), replacement)
        self.c.replace.assert_called_once_with(self.x, self.x, replacement)
        with self.assertRaises(ValueError):
            ast_tools.replace(self.c, self.x, self.x, self.BV('BVS', ('y', 16), 16))
        self.assertEqual(self.c.replace.call_count, 1)


class ProcessBoundaryTests(unittest.TestCase):
    def query(self):
        return SolverQuery((equals(symbol(), const()),), origin="process-boundary-test")

    def test_memory_rejected_before_subprocess(self):
        with mock.patch("emtaint.solver.process_port.subprocess.Popen") as spawn:
            q = SolverQuery((equals(Term("Load", 32, (symbol(),)), const()),))
            result = SubprocessSolverPort().solve(q)
            self.assertEqual(result.status, SolverStatus.UNSUPPORTED)
            spawn.assert_not_called()

    def test_launch_failure_is_an_error(self):
        with mock.patch("emtaint.solver.process_port.subprocess.Popen", side_effect=OSError("fixture")):
            result = SubprocessSolverPort().solve(self.query())
        self.assertEqual(result.status, SolverStatus.ERROR)
        self.assertIn("launch failed", result.reason)

    def test_invalid_worker_model_is_rejected(self):
        import json
        def bad_worker(command, **kwargs):
            folder = Path(command[-1])
            result = SolverResult(SolverStatus.SAT, values=(256,))
            (folder / "result.json").write_text(json.dumps(result.to_dict()))
            return types.SimpleNamespace(returncode=0, wait=lambda timeout: 0)
        q = SolverQuery((equals(symbol(width=8), const(7, 8)),), symbol(width=8), "eval")
        with mock.patch("emtaint.solver.process_port.subprocess.Popen", side_effect=bad_worker):
            result = SubprocessSolverPort().solve(q)
        self.assertEqual(result.status, SolverStatus.ERROR)
        self.assertIn("model", result.reason)

    def test_native_exit_is_contained_and_never_unsat(self):
        if sys.platform != "win32":
            self.skipTest("Windows exit-code containment")
        import subprocess
        real_spawn = subprocess.Popen
        def injected_exit(command, **kwargs):
            return real_spawn([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c',
                               'import ctypes; ctypes.windll.kernel32.ExitProcess(0xC0000005)'], **kwargs)
        with mock.patch("emtaint.solver.process_port.subprocess.Popen", side_effect=injected_exit):
            result = SubprocessSolverPort().solve(self.query())
        self.assertEqual(result.status, SolverStatus.CRASH)
        self.assertEqual(result.values, ())
        self.assertTrue((Path(result.evidence) / "process.json").is_file())

    def test_wall_deadline_kills_venv_worker_tree(self):
        import subprocess
        real_spawn = subprocess.Popen
        def injected_sleep(command, **kwargs):
            return real_spawn([str(ROOT / '.venv/Scripts/python.exe'), '-B', '-c',
                               'import time; time.sleep(20)'], **kwargs)
        with mock.patch("emtaint.solver.process_port.subprocess.Popen", side_effect=injected_sleep):
            result = SubprocessSolverPort(wall_timeout=1).solve(self.query())
        self.assertEqual(result.status, SolverStatus.TIMEOUT)
        self.assertIn("worker tree terminated", result.reason)


if __name__ == "__main__":
    unittest.main()
