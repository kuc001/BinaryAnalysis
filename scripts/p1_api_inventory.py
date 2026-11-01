"""Static native import/call/attribute inventory; candidates are not runtime proof."""
import ast
import re
from pathlib import Path

NATIVE = {"angr", "claripy", "pyvex", "cle", "archinfo", "z3"}
ATTRIBUTES = {"op", "args", "variables", "annotations", "cache_key", "recursive_children_asts",
              "recursive_leaf_asts", "replace", "simplify", "size", "depth", "solver", "memory",
              "satisfiable", "eval", "eval_one", "min", "max", "vex", "factory", "loader"}


def inventory(root):
    root = Path(root)
    records, errors, files = [], [], 0
    for path in sorted(root.rglob("*.py")):
        relative = path.relative_to(root)
        if any(part in {".git", ".venv", "__pycache__", ".p1-work"} for part in relative.parts):
            continue
        files += 1
        try:
            tree = ast.parse(path.read_text(encoding="utf-8-sig"), filename=str(path))
        except (SyntaxError, UnicodeError) as error:
            errors.append({"file": relative.as_posix(), "error": str(error), "line": getattr(error, "lineno", None)})
            for line, text in enumerate(path.read_text(encoding="utf-8-sig", errors="replace").splitlines(), 1):
                if re.search(r"\b(?:angr|claripy|pyvex|cle|archinfo|z3)\b|\.\s*(?:solver|replace|cache_key|recursive_children_asts)\b", text):
                    records.append({"file": relative.as_posix(), "line": line,
                                    "kind": "syntax_error_text_candidate", "api": text.strip()})
            continue
        aliases = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".")[0] in NATIVE:
                        aliases[alias.asname or alias.name.split(".")[0]] = alias.name
                        records.append({"file": relative.as_posix(), "line": node.lineno,
                                        "kind": "native_import", "api": alias.name})
            elif isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] in NATIVE:
                for alias in node.names:
                    aliases[alias.asname or alias.name] = (node.module or "") + "." + alias.name
                    records.append({"file": relative.as_posix(), "line": node.lineno,
                                    "kind": "native_import", "api": aliases[alias.asname or alias.name]})
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                text = ast.unparse(node.func)
                first = text.split(".")[0]
                if first in aliases:
                    records.append({"file": relative.as_posix(), "line": node.lineno,
                                    "kind": "import_resolved_call", "api": aliases[first] + text[len(first):]})
                elif text.endswith(tuple("." + n for n in ATTRIBUTES)) or text in ("BVS", "BVV"):
                    records.append({"file": relative.as_posix(), "line": node.lineno,
                                    "kind": "unresolved_call_candidate", "api": text})
            elif isinstance(node, ast.Attribute) and node.attr in ATTRIBUTES:
                records.append({"file": relative.as_posix(), "line": node.lineno,
                                "kind": "attribute_candidate", "api": ast.unparse(node)})
    return {"files_scanned": files, "parse_errors": errors, "records": records,
            "note": "File-level import aliases; rebinding/dynamic dispatch require manual verification. Candidates are not confirmed native objects."}
