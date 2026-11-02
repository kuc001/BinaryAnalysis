"""Audit Python quality contracts and internal module dependencies.

The repository intentionally has no third-party lint or type-checking dependency.
This tool therefore provides a deterministic, read-only AST baseline for safety
violations, documentation/type debt, imports, and strongly connected components.
It does not replace a real type checker and never rewrites source files.
"""

from __future__ import annotations

import argparse
import ast
from collections import Counter
from dataclasses import asdict, dataclass
import json
from pathlib import Path
from typing import Iterable, Sequence


SAFETY_CODES = frozenset(
    {"syntax-error", "bare-except", "silent-exception", "wildcard-import"}
)


@dataclass(frozen=True, order=True)
class Finding:
    """One source-level quality finding with a stable machine-readable code."""

    path: str
    line: int
    code: str
    message: str


@dataclass(frozen=True)
class AuditReport:
    """Immutable result of one audit run.

    Import edges use canonical module names. A component with more than one
    member is a circular dependency and must be reviewed as one batch.
    """

    files: int
    modules: int
    import_edges: tuple[tuple[str, str], ...]
    components: tuple[tuple[str, ...], ...]
    findings: tuple[Finding, ...]

    @property
    def cycles(self) -> tuple[tuple[str, ...], ...]:
        """Return only non-trivial strongly connected components."""

        return tuple(component for component in self.components if len(component) > 1)

    def counts(self) -> dict[str, int]:
        """Count findings by stable code."""

        return dict(sorted(Counter(item.code for item in self.findings).items()))

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible report without losing dependency ordering."""

        return {
            "files": self.files,
            "modules": self.modules,
            "import_edges": [list(edge) for edge in self.import_edges],
            "cycles": [list(component) for component in self.cycles],
            "finding_counts": self.counts(),
            "findings": [asdict(item) for item in self.findings],
        }


def _module_name(source_root: Path, path: Path) -> str:
    """Map a Python path below ``source_root`` to its importable module name."""

    relative = path.relative_to(source_root.parent).with_suffix("")
    parts = relative.parts
    if parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def _target_module(name: str, modules: frozenset[str]) -> str | None:
    """Resolve an import to the nearest module represented in the audit set."""

    candidate = name
    while candidate:
        if candidate in modules:
            return candidate
        candidate = candidate.rpartition(".")[0]
    return None


def _relative_import(package: str, node: ast.ImportFrom) -> str:
    """Resolve a relative import without importing or executing the package."""

    if node.level == 0:
        return node.module or ""
    parts = package.split(".") if package else []
    keep = max(0, len(parts) - (node.level - 1))
    prefix = ".".join(parts[:keep])
    return ".".join(part for part in (prefix, node.module or "") if part)


def _import_names(node: ast.AST, package: str) -> tuple[str, ...]:
    """Return statically knowable imports, including constant dynamic imports."""

    if isinstance(node, ast.Import):
        return tuple(alias.name for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        base = _relative_import(package, node)
        imported_modules = tuple(
            f"{base}.{alias.name}" for alias in node.names if alias.name != "*" and base
        )
        return (base, *imported_modules)
    if not isinstance(node, ast.Call) or not node.args:
        return ()
    first = node.args[0]
    if not isinstance(first, ast.Constant) or not isinstance(first.value, str):
        return ()
    if isinstance(node.func, ast.Name) and node.func.id == "__import__":
        return (first.value,)
    if isinstance(node.func, ast.Attribute) and node.func.attr == "import_module":
        return (first.value,)
    return ()


def _callable_has_complete_types(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Check explicit parameter and return annotations without guessing types."""

    arguments = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    arguments = [argument for argument in arguments if argument.arg not in {"self", "cls"}]
    if any(argument.annotation is None for argument in arguments):
        return False
    if node.args.vararg is not None and node.args.vararg.annotation is None:
        return False
    if node.args.kwarg is not None and node.args.kwarg.annotation is None:
        return False
    return node.returns is not None


def _is_silent_handler(node: ast.ExceptHandler) -> bool:
    """Detect handlers whose entire body discards an exception."""

    return bool(node.body) and all(isinstance(statement, ast.Pass) for statement in node.body)


def _audit_tree(path: Path, tree: ast.Module) -> list[Finding]:
    """Collect local findings without executing the parsed module."""

    display = path.as_posix()
    findings: list[Finding] = []
    parents = {
        child: parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    if ast.get_docstring(tree) is None:
        findings.append(Finding(display, 1, "missing-module-doc", "Module has no docstring"))

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and any(alias.name == "*" for alias in node.names):
            findings.append(
                Finding(display, node.lineno, "wildcard-import", "Wildcard import obscures dependencies")
            )
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                findings.append(
                    Finding(display, node.lineno, "bare-except", "Catch a specific exception type")
                )
            if _is_silent_handler(node):
                findings.append(
                    Finding(display, node.lineno, "silent-exception", "Exception handler silently passes")
                )
        if (
            isinstance(node, ast.ClassDef)
            and isinstance(parents.get(node), ast.Module)
            and not node.name.startswith("_")
        ):
            if ast.get_docstring(node) is None:
                findings.append(
                    Finding(display, node.lineno, "missing-class-doc", f"Public class {node.name} has no docstring")
                )
        if (
            isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
            and isinstance(parents.get(node), (ast.Module, ast.ClassDef))
            and not node.name.startswith("_")
        ):
            if ast.get_docstring(node) is None:
                findings.append(
                    Finding(
                        display,
                        node.lineno,
                        "missing-callable-doc",
                        f"Public callable {node.name} has no docstring",
                    )
                )
            if not _callable_has_complete_types(node):
                findings.append(
                    Finding(
                        display,
                        node.lineno,
                        "missing-callable-type",
                        f"Public callable {node.name} lacks complete annotations",
                    )
                )
    return findings


def _strong_components(
    modules: Iterable[str], edges: dict[str, set[str]]
) -> tuple[tuple[str, ...], ...]:
    """Return Tarjan SCCs in deterministic member and component order."""

    next_index = 0
    stack: list[str] = []
    on_stack: set[str] = set()
    indices: dict[str, int] = {}
    low_links: dict[str, int] = {}
    components: list[tuple[str, ...]] = []

    def _visit(module: str) -> None:
        nonlocal next_index
        indices[module] = next_index
        low_links[module] = next_index
        next_index += 1
        stack.append(module)
        on_stack.add(module)

        for dependency in sorted(edges[module]):
            if dependency not in indices:
                _visit(dependency)
                low_links[module] = min(low_links[module], low_links[dependency])
            elif dependency in on_stack:
                low_links[module] = min(low_links[module], indices[dependency])

        if low_links[module] != indices[module]:
            return
        component: list[str] = []
        while True:
            member = stack.pop()
            on_stack.remove(member)
            component.append(member)
            if member == module:
                break
        components.append(tuple(sorted(component)))

    for module in sorted(modules):
        if module not in indices:
            _visit(module)
    return tuple(sorted(components))


def audit(source_root: Path, selected_paths: Sequence[Path] = ()) -> AuditReport:
    """Audit Python files and imports beneath one package source root.

    Args:
        source_root: Package directory, normally ``emtaint``.
        selected_paths: Optional files to restrict local findings. Dependency
            resolution still reads the complete package so SCCs remain valid.

    Raises:
        ValueError: If the source root or a selected path is outside the package.
    """

    source_root = source_root.resolve()
    if not source_root.is_dir():
        raise ValueError(f"Source root is not a directory: {source_root}")
    all_paths = tuple(sorted(source_root.rglob("*.py")))
    module_by_path = {path: _module_name(source_root, path) for path in all_paths}
    modules = frozenset(module_by_path.values())
    edges: dict[str, set[str]] = {module: set() for module in modules}
    findings: list[Finding] = []

    selected = {path.resolve() for path in selected_paths}
    unknown = selected.difference(all_paths)
    if unknown:
        names = ", ".join(str(path) for path in sorted(unknown))
        raise ValueError(f"Selected paths are not Python files below {source_root}: {names}")

    for path, module in module_by_path.items():
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (OSError, UnicodeError, SyntaxError) as error:
            findings.append(Finding(path.as_posix(), 1, "syntax-error", str(error)))
            continue
        if not selected or path in selected:
            findings.extend(_audit_tree(path, tree))
        package = module if path.name == "__init__.py" else module.rpartition(".")[0]
        for node in ast.walk(tree):
            for name in _import_names(node, package):
                if not name.startswith(source_root.name):
                    continue
                target = _target_module(name, modules)
                if target is not None and target != module:
                    edges[module].add(target)

    import_edges = tuple(
        (module, dependency)
        for module in sorted(edges)
        for dependency in sorted(edges[module])
    )
    return AuditReport(
        files=len(all_paths),
        modules=len(modules),
        import_edges=import_edges,
        components=_strong_components(modules, edges),
        findings=tuple(sorted(findings)),
    )


def _exit_code(report: AuditReport, fail_on: str) -> int:
    """Translate the selected enforcement level into a process exit code."""

    if fail_on == "none":
        return 0
    if fail_on == "safety":
        return int(any(item.code in SAFETY_CODES for item in report.findings))
    return int(bool(report.findings))


def _parser() -> argparse.ArgumentParser:
    """Build the command-line contract in one testable location."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, default=Path("emtaint"))
    parser.add_argument("--path", action="append", type=Path, default=[])
    parser.add_argument("--json", action="store_true", help="Emit the complete JSON report")
    parser.add_argument(
        "--fail-on",
        choices=("none", "safety", "all"),
        default="none",
        help="Select which findings make the command fail",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the read-only audit CLI and return a conventional exit status."""

    args = _parser().parse_args(argv)
    try:
        report = audit(args.source_root, args.path)
    except ValueError as error:
        _parser().error(str(error))
    if args.json:
        print(json.dumps(report.to_dict(), indent=2, sort_keys=True))
    else:
        print(
            f"files={report.files} modules={report.modules} "
            f"edges={len(report.import_edges)} cycles={len(report.cycles)}"
        )
        print("findings=" + json.dumps(report.counts(), sort_keys=True))
        for component in report.cycles:
            print("cycle=" + ",".join(component))
    return _exit_code(report, args.fail_on)


if __name__ == "__main__":
    raise SystemExit(main())
