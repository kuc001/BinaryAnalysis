"""Lifecycle regressions for query-local P7 budget management."""

from types import SimpleNamespace
import unittest
from unittest.mock import patch

try:
    from test_p3_contracts import fixture as _fixture  # noqa: F401
except ModuleNotFoundError:
    from tests.test_p3_contracts import fixture as _fixture  # noqa: F401

from emtaint.analysis.dataflow.legacy_demand import DemandLimit
from emtaint.analysis.taint.demand_budget import QueryBudgetController


class QueryBudgetControllerTests(unittest.TestCase):
    def make_owner(self):
        calls=[]

        def validate():
            calls.append("validate")

        previous=lambda dimension, observed: calls.append(
            (dimension, observed)
        )
        accounting=SimpleNamespace(
            observer=previous,
            counts={"worklist_iterations": 7},
        )
        owner=SimpleNamespace(
            port=SimpleNamespace(
                engine=SimpleNamespace(accounting=accounting),
                validate_current=validate,
            ),
            demand=SimpleNamespace(steps=11, query_scalar_limit=40),
            query_step_limit=30,
            query_work_limit=50,
            query_clock_limit=None,
            current_query="query-1",
            argument_preparations=[],
        )
        return owner, calls, previous, validate

    def test_nested_lifecycle_restores_hooks_after_exception(self):
        owner, _, previous, validate= self.make_owner()
        controller=QueryBudgetController(owner)
        with self.assertRaisesRegex(RuntimeError, "stop"):
            with controller.query_lifecycle():
                outer_observer=owner.port.engine.accounting.observer
                outer_validate=owner.port.validate_current
                with controller.query_lifecycle():
                    self.assertIsNot(
                        owner.port.engine.accounting.observer,
                        outer_observer,
                    )
                    self.assertIsNot(
                        owner.port.validate_current, outer_validate
                    )
                self.assertIs(
                    owner.port.engine.accounting.observer, outer_observer
                )
                self.assertIs(owner.port.validate_current, outer_validate)
                raise RuntimeError("stop")
        self.assertIs(owner.port.engine.accounting.observer, previous)
        self.assertIs(owner.port.validate_current, validate)
        self.assertIsNone(owner.query_step_limit)
        self.assertIsNone(owner.query_work_limit)
        self.assertIsNone(owner.query_clock_limit)
        self.assertIsNone(owner.demand.query_scalar_limit)

    def test_argument_preparation_restores_shares_after_exception(self):
        owner, _, _, _=self.make_owner()
        controller=QueryBudgetController(owner)
        call=SimpleNamespace(origin="call-origin")
        with self.assertRaisesRegex(RuntimeError, "argument failed"):
            with controller.argument_preparation(call, 2) as state:
                self.assertIsNone(owner.demand.query_scalar_limit)
                self.assertIsNone(owner.query_work_limit)
                self.assertIsNone(owner.query_clock_limit)
                owner.demand.steps+=3
                owner.port.engine.accounting.counts[
                    "worklist_iterations"
                ]+=5
                state["status"]="incomplete"
                raise RuntimeError("argument failed")
        self.assertEqual(owner.demand.query_scalar_limit, 43)
        self.assertEqual(owner.query_work_limit, 55)
        self.assertIsNone(owner.query_clock_limit)
        self.assertEqual(
            owner.argument_preparations[0]["status"], "incomplete"
        )

    def test_deadline_failure_keeps_query_dimension(self):
        owner, _, _, _=self.make_owner()
        owner.query_clock_limit=10.0
        controller=QueryBudgetController(owner)
        with patch(
                "emtaint.analysis.taint.demand_budget.time.monotonic",
                return_value=10.1):
            with self.assertRaises(DemandLimit) as raised:
                controller.check_query_clock()
        self.assertEqual(raised.exception.dimension, "query")


if __name__ == "__main__":
    unittest.main()
