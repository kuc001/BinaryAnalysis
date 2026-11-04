"""Compatibility locks for the public P7 demand model and evidence schema."""

from dataclasses import fields
import inspect
import json
from pathlib import Path
import unittest

# The shared contract fixture initializes the repository-local import path in
# the same way as the other direct P7 test modules.
try:
    from test_p3_contracts import fixture as _fixture  # noqa: F401
except ModuleNotFoundError:
    from tests.test_p3_contracts import fixture as _fixture  # noqa: F401

from emtaint.analysis.taint.demand import (
    BufferDestination,
    ConstraintRecipe,
    DeferredFormatArgument,
    LegacyTaintDemand,
    ProcedureDemand,
    SinkRequirement,
    TaintDependency,
    TaintProcedureSummary,
    dependency_order,
    sink_order,
)
from emtaint.analysis.taint.evidence import summary_evidence


FIXTURE_DIRECTORY = Path(__file__).with_name("fixtures")


def fixed_summary() -> TaintProcedureSummary:
    """Build a stable summary covering nested dependencies and recipes."""
    recipe = ConstraintRecipe(
        "fixed-recipe", BufferDestination("argument", 2, 4)
    )
    source = TaintDependency(
        kind="source",
        value=7,
        constraints=(16,),
        path=(0x30, 0x10),
        guards=(("equal", 1),),
        handles=(("fd", 3),),
        recipes=(recipe,),
        access_width=32,
        byte_access=True,
        constraint_type=4,
    )
    selector = TaintDependency(
        kind="format_argument",
        value=DeferredFormatArgument(
            format_slot=0,
            position=2,
            dependency=TaintDependency(
                kind="argument", value=1, offset=8
            ),
        ),
        uncertain=True,
        offset=None,
        unresolved_constraints=True,
    )
    sink = SinkRequirement(
        function=0x1000,
        site=0x1010,
        name="system",
        kind="command",
        offsets=(12, 4),
        dependencies=(source, selector),
        origin="fixture-origin",
        constraints=(("maximum", 64),),
        guards=(("nonzero", "r0"),),
        destinations=(BufferDestination("stack", -12, 0),),
        weak_kind="copy",
        length_dependencies=(selector,),
    )
    return TaintProcedureSummary(
        function=0x1000,
        returns=(source,),
        outputs=((0, (selector, source)),),
        sinks=(sink,),
        pending=(("query", "budget"),),
        tables=(),
        scalar_returns=(selector,),
        global_outputs=None,
    )


class DemandCompatibilityTests(unittest.TestCase):
    """Detect accidental public ABI or replay evidence changes."""

    def test_public_constructor_parameter_order_is_stable(self):
        expected = {
            ConstraintRecipe: ("key", "value"),
            TaintDependency: (
                "kind",
                "value",
                "constraints",
                "path",
                "uncertain",
                "guards",
                "handles",
                "offset",
                "recipes",
                "access_width",
                "byte_access",
                "unresolved_constraints",
                "constraint_type",
            ),
            DeferredFormatArgument: (
                "format_slot",
                "position",
                "dependency",
            ),
            BufferDestination: ("kind", "value", "offset"),
            SinkRequirement: (
                "function",
                "site",
                "name",
                "kind",
                "offsets",
                "dependencies",
                "origin",
                "constraints",
                "guards",
                "destinations",
                "weak_kind",
                "length_dependencies",
            ),
            TaintProcedureSummary: (
                "function",
                "returns",
                "outputs",
                "sinks",
                "pending",
                "tables",
                "scalar_returns",
                "global_outputs",
            ),
            ProcedureDemand: (
                "function",
                "port",
                "cfg",
                "initial",
                "budget",
                "summaries",
                "names",
                "cache_queries",
            ),
            LegacyTaintDemand: (
                "function",
                "port",
                "cfg",
                "initial",
                "names",
                "summaries",
                "targets",
                "image_base",
                "max_steps",
                "max_dependencies",
                "cache_queries",
                "tables",
                "function_deadline",
            ),
        }
        for public_type, names in expected.items():
            with self.subTest(public_type=public_type.__name__):
                self.assertEqual(
                    tuple(inspect.signature(public_type).parameters), names
                )

        self.assertEqual(tuple(inspect.signature(dependency_order).parameters),
                         ("dep",))
        self.assertEqual(tuple(inspect.signature(sink_order).parameters),
                         ("sink",))

    def test_dataclass_field_order_and_repr_contract_are_stable(self):
        summary = fixed_summary()
        self.assertEqual(
            tuple(field.name for field in fields(TaintDependency)),
            (
                "kind",
                "value",
                "constraints",
                "path",
                "uncertain",
                "guards",
                "handles",
                "offset",
                "recipes",
                "access_width",
                "byte_access",
                "unresolved_constraints",
                "constraint_type",
            ),
        )
        recipe = summary.returns[0].recipes[0]
        self.assertEqual(repr(recipe),
                         "ConstraintRecipe(key='fixed-recipe')")
        self.assertEqual(
            hash(recipe), hash(ConstraintRecipe("fixed-recipe", object()))
        )

    def test_fixed_summary_evidence_matches_byte_for_byte_fixture(self):
        encoded = json.dumps(
            summary_evidence(fixed_summary()),
            sort_keys=True,
            separators=(",", ":"),
        )
        expected = (
            FIXTURE_DIRECTORY / "p7_demand_evidence.json"
        ).read_bytes()
        self.assertEqual((encoded + "\n").encode("utf-8"), expected)

    def test_ordering_keeps_path_guard_and_recipe_evidence(self):
        summary = fixed_summary()
        source = summary.returns[0]
        changed_path = TaintDependency(
            **{**source.__dict__, "path": (0x10, 0x30)}
        )
        changed_guard = TaintDependency(
            **{**source.__dict__, "guards": (("equal", 2),)}
        )
        # Path identity is deliberately handled by source_antichain rather
        # than by the historical dependency ordering key.
        self.assertEqual(dependency_order(source),
                         dependency_order(changed_path))
        self.assertNotEqual(dependency_order(source),
                            dependency_order(changed_guard))
        self.assertEqual(changed_path.path, (0x10, 0x30))
        self.assertEqual(source.path, (0x30, 0x10))
        sink = summary.sinks[0]
        self.assertEqual(sink_order(sink), sink_order(summary.sinks[0]))


if __name__ == "__main__":
    unittest.main()
