"""CLI adapter for native binary alias queries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .program import NativeAliasProgram


def run_alias_cli(args) -> int:
    """Run a query without requiring firmware acquisition or IDA metadata."""

    root = Path(__file__).resolve().parents[3]
    folder = Path(args.output).resolve()
    folder.relative_to(root / ".debug")
    binary = Path(args.binary_file).resolve()
    if not binary.is_file():
        raise FileNotFoundError(binary)
    # Alias queries are routinely rerun against the same debug case.  Reuse an
    # existing directory while still letting ``mkdir`` reject a same-name file.
    folder.mkdir(parents=True, exist_ok=True)
    program = NativeAliasProgram(
        binary, tuple(args.observe_call),
    )
    if not args.discover_alias_calls:
        program.roots = (
            int(args.function, 0)
            if args.function.startswith(("0x", "0X"))
            else program._symbol_address(args.function),
        )
    if args.discover_alias_calls:
        observations = [
            {
                "function": function,
                "site": site,
                "observer": observer,
                "predicted": predicted,
                "alias_kinds": list(kinds),
                "evidence": list(evidence),
                "complete": complete,
                "reason_codes": list(reasons),
            }
            for function, site, observer, predicted, kinds, evidence,
            complete, reasons in program.query_calls()
        ]
    else:
        result = program.query_call_locators(
            args.function, args.site, args.left, args.right,
        )
        predicted, kinds, evidence, complete, reasons = result
        observations = [{
            "function": args.function,
            "site": args.site,
            "left": args.left,
            "right": args.right,
            "predicted": predicted,
            "alias_kinds": list(kinds),
            "evidence": list(evidence),
            "complete": complete,
            "reason_codes": list(reasons),
        }]
    report = {
        "schema": "emtaint-alias-query-v1",
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "observations": observations,
        "diagnostics": program.diagnostics,
        "complete": all(
            item["complete"] for item in observations
        ),
    }
    (folder / "alias-query.json").write_text(
        json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0 if report["complete"] else 2
