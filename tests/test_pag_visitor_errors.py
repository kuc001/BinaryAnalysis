"""Characterize fail-closed exception handling in the legacy PAG visitor."""

from pathlib import Path
import tempfile
import unittest

# pyvex generates an FFI parser cache during import. Keep that native-library
# side effect in the repository's ignored test workspace under Windows sandboxing.
_original_tempdir = tempfile.tempdir
tempfile.tempdir = str(Path(__file__).resolve().parents[1] / ".p7-work")
try:
    from emtaint.analysis.pag.visitor import PAGVisitor
    from emtaint.analysis.variables.binop_value import BinopValue
    from emtaint.analysis.variables.unop_value import UnopValue
    from emtaint.analysis.variables.value import ValueKind
    from emtaint.ir.expressions.unop import Unop as UnaryExpression
finally:
    tempfile.tempdir = _original_tempdir


class _Named:
    def __init__(self, value: str | int) -> None:
        self.value = value

    def get_name(self) -> str | int:
        return self.value


class _BrokenName:
    def get_name(self) -> str:
        raise ValueError("invalid expression fixture")


class _Conditional:
    def get_cond(self) -> _BrokenName:
        return _BrokenName()

    def get_iftrue(self) -> _Named:
        return _Named("t1")

    def get_iffalse(self) -> _Named:
        return _Named("t2")


class _WrITE:
    def get_def(self) -> str:
        return "t3"

    def get_use(self) -> _Conditional:
        return _Conditional()


class _LoadG:
    def get_guard(self) -> _BrokenName:
        return _BrokenName()

    def get_def(self) -> str:
        return "t3"

    def get_use_with_guard(self) -> _Named:
        return _Named("t1")

    def get_use_without_guard(self) -> _Named:
        return _Named("t2")


class _StoreG:
    def get_guard(self) -> _BrokenName:
        return _BrokenName()

    def get_def(self) -> _Named:
        return _Named("t1")

    def get_use(self) -> _Named:
        return _Named("t2")


class _BrokenArgument:
    def __init__(self, error: BaseException | None = None) -> None:
        self.error = error or KeyError("missing temporary fixture")

    def accept(self, visitor: PAGVisitor) -> object:
        raise self.error


class _Operation:
    def __init__(self, argument: _BrokenArgument) -> None:
        self.args = (argument,)

    def get_size(self) -> int:
        return 32


class PAGVisitorErrorTests(unittest.TestCase):
    """Verify contextual errors, chaining, and non-capture of interrupts."""

    def setUp(self) -> None:
        self.visitor = PAGVisitor(object())

    def test_guarded_statements_preserve_cause_and_statement_context(self) -> None:
        """Malformed guarded expressions raise ValueError with a real cause."""

        cases = (
            (self.visitor.visit_wr_ite, _WrITE(), "WrITE"),
            (self.visitor.visit_loadg, _LoadG(), "LoadG"),
            (self.visitor.visit_storeg, _StoreG(), "StoreG"),
        )
        for visit, statement, label in cases:
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, label) as raised:
                    visit(statement)
                self.assertIsInstance(raised.exception.__cause__, ValueError)

    def test_scalar_operations_preserve_argument_context(self) -> None:
        """Expression contract failures identify binop/unop and retain causes."""

        for visit, label in (
            (self.visitor.visit_binop, "Binop"),
            (self.visitor.visit_unop, "Unop"),
        ):
            with self.subTest(label=label):
                with self.assertRaisesRegex(ValueError, label) as raised:
                    visit(_Operation(_BrokenArgument()))
                self.assertIsInstance(raised.exception.__cause__, KeyError)

    def test_process_control_exceptions_are_not_hidden(self) -> None:
        """Keyboard interrupts bypass the expression-contract conversion."""

        with self.assertRaises(KeyboardInterrupt):
            self.visitor.visit_binop(
                _Operation(_BrokenArgument(KeyboardInterrupt("stop fixture")))
            )

    def test_legacy_value_wrappers_reject_non_values_explicitly(self) -> None:
        """Invalid BinopValue/UnopValue operands raise TypeError, not ``None``."""

        for wrapper in (BinopValue, UnopValue):
            with self.subTest(wrapper=wrapper.__name__), self.assertRaisesRegex(
                TypeError, "Value instances"
            ):
                wrapper("Iop_Add32", (object(),), 32, ValueKind.Unknown)

    def test_unary_expression_preserves_missing_name_cause(self) -> None:
        """The legacy expression adapter adds context to malformed operands."""

        expression = type("ExpressionFixture", (), {"args": (object(),)})()
        with self.assertRaisesRegex(ValueError, "get_name") as raised:
            UnaryExpression.get_args_info(expression)
        self.assertIsInstance(raised.exception.__cause__, AttributeError)


if __name__ == "__main__":
    unittest.main()
