"""Public acquisition and detached inspection commands for F1."""
import argparse
import json
from pathlib import Path
import sys

from emtaint.f1_acquisition import F1Project, acquire_f1
from emtaint.f1_artifacts import F1Reference, load_f1


def main(argv: list[str]) -> int:
    """Run F1 acquisition or inspect persisted analysis inputs."""
    parser = argparse.ArgumentParser(prog="python -m emtaint f1")
    commands = parser.add_subparsers(dest="command", required=True)
    acquire = commands.add_parser("acquire")
    acquire.add_argument("--project", type=Path, required=True)
    acquire.add_argument("--artifact-root", type=Path, required=True)
    inspect = commands.add_parser("inspect")
    inspect.add_argument("--generation", type=Path, required=True)
    inspect.add_argument("--manifest-sha256", required=True)
    inspect.add_argument("--related", nargs=2, metavar=("KIND", "ID"))
    args = parser.parse_args(argv)
    try:
        reference = (acquire_f1(F1Project.from_file(args.project), args.artifact_root)
                     if args.command == "acquire" else F1Reference(args.generation, args.manifest_sha256))
        loaded = load_f1(reference)
        result = {
            "generation": str(reference.generation), "manifest_sha256": reference.manifest_sha256,
            "binary_sha256": loaded.hir.function.binary.sha256, "rva": f"0x{loaded.hir.function.rva:x}",
            "integrity": loaded.integrity.value, "semantic_completeness": loaded.semantic_completeness.value,
            "hir_nodes": len(loaded.hir.nodes), "cfg_blocks": len(loaded.cfg.nodes),
            "cfg_edges": len(loaded.cfg.edges), "provenance_edges": len(loaded.provenance.edges),
            "diagnostics": loaded.cir.diagnostics,
        }
        if args.command == "inspect" and args.related:
            result["related"] = loaded.provenance.related(*args.related)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError) as error:
        print(str(error), file=sys.stderr)
        return 1
