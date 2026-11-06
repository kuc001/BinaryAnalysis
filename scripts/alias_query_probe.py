"""Read-only CIR/demand snapshot for a binary alias observer callsite."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from emtaint.analysis.aliasing.program import NativeAliasProgram
from emtaint.ir.canonical import CallEffect


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--observer", required=True)
    parser.add_argument("--site", required=True, type=lambda value: int(value, 0))
    arguments = parser.parse_args()
    program = NativeAliasProgram(arguments.binary.resolve(), (arguments.observer,))
    program.query_calls()
    for item in program.lifted.values():
        for block in item.function.blocks:
            for effect in block.effects:
                if not isinstance(effect, CallEffect):
                    continue
                site = program.base + (effect.site.point.instruction_rva or 0)
                if site != arguments.site:
                    continue
                demand = program._demand(item)
                print("function", item.name, "site", hex(site), "block", block.id)
                symbol = program.frontend.project.loader.find_symbol(item.name)
                if symbol is not None and symbol.size:
                    native = program.frontend.project.factory.block(
                        int(symbol.rebased_addr), size=int(symbol.size),
                        opt_level=0, cross_insn_opt=False,
                    )
                    print("assembly", native.capstone)
                print("call", repr(effect))
                print("summary-stores", [
                    (hex(fid.rva), len(recipe.stores), recipe.unknown_effects)
                    for fid, recipe in program.summaries.items()
                    if recipe is not None
                ])
                for fid, recipe in program.summaries.items():
                    if recipe is None or not recipe.stores:
                        continue
                    print("recipe", hex(fid.rva), [
                        [(root, recipe.nodes[root].op, recipe.nodes[root].value)
                         for root in store.values]
                        for store in recipe.stores
                    ])
                    if len(recipe.stores) > 1:
                        print("recipe-nodes", hex(fid.rva), [
                            (index, node.op, node.value, node.operands)
                            for index, node in enumerate(recipe.nodes)
                        ])
                for previous_block in item.function.blocks:
                    for previous in previous_block.effects:
                        if not isinstance(previous, CallEffect):
                            continue
                        target = getattr(previous.target, "function", None)
                        recipe = program.summaries.get(target)
                        if recipe is None or not recipe.stores:
                            continue
                        print("callee", hex(target.rva), "at", previous.origin)
                        print("callee-arguments", [
                            [repr(demand.address_binding(value))
                             for value in demand.value(argument)]
                            for argument in previous.arguments[:4]
                        ])
                        for store in recipe.stores:
                            addresses = recipe.addresses(demand, previous, store, 0)
                            values = recipe.stored_values(demand, previous, store, 0)
                            print("store", store.width_bits, store.must_execute,
                                  "addresses", [(repr(address), repr(demand.address_binding(address)))
                                                for address in addresses],
                                  "values", [repr(value) for value in values])
                            for stored_value, _ in values:
                                node = demand.port.engine.dag.nodes[stored_value]
                                print("store-value-node", node.op, node.value,
                                      [demand.port.engine.dag.nodes[operand].op
                                       for operand in node.operands])
                for index, operand in enumerate(effect.arguments[:2]):
                    values = demand.value(operand)
                    print("argument", index, "operand", repr(operand))
                    for value in values:
                        print("value", repr(value))
                        print("node", repr(demand.port.engine.dag.nodes.get(value)))
                        print("binding", repr(demand.address_binding(value)))
                return 0
    raise ValueError("Requested callsite was not discovered")


if __name__ == "__main__":
    raise SystemExit(main())
