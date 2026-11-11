"""Minimal F0 acquisition command, separate from the legacy analysis CLI."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from emtaint.acquisition import FrontendSelection, acquire
from emtaint.artifacts import ArtifactError, ArtifactRoot
from emtaint.frontends.inputs import InputError
from emtaint.project import ProjectSpec, resolve


def main(argv: list[str] | None = None) -> int:
    """Acquire one declared function and print its pinned acquisition receipt."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project", type=Path, required=True)
    parser.add_argument("--artifact-root", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        spec = ProjectSpec.from_file(args.project)
        inputs = resolve(spec)
        outcome = acquire(inputs, FrontendSelection(spec.frontend),
                          ArtifactRoot(args.artifact_root.resolve()))
    except (ArtifactError, InputError, OSError, json.JSONDecodeError) as error:
        status = error.status.value if isinstance(error, ArtifactError) else "error"
        print(json.dumps({"status": status, "error": str(error)}), file=sys.stderr)
        return 2
    print(json.dumps({
        "schema_version": outcome.reference.schema_version,
        "generation": str(outcome.reference.generation),
        "manifest_sha256": outcome.reference.manifest_sha256,
        "binary_sha256": outcome.function.binary.sha256,
        "function_rva": outcome.function.rva,
        "artifact_integrity": outcome.integrity.value,
        "semantic_completeness": outcome.semantic_completeness.value,
        "diagnostics": outcome.diagnostics,
    }, sort_keys=True))
    return 0
