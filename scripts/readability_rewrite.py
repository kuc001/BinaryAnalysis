"""Apply conservative, token-aware Python readability rewrites.

The command changes only two mechanically safe forms: whitespace after a
comma, and semicolons separating simple statements on a line without a suite
colon. Strings and comments are tokens and are never rewritten. Complex
one-line suites remain visible to ``quality_audit.py`` for manual cleanup.
"""

from __future__ import annotations

import argparse
import io
from pathlib import Path
import tokenize
from typing import Sequence


def rewrite_source(source: str) -> str:
    """Return source with safe comma spacing and simple statements expanded."""

    rows = source.splitlines(keepends=True)
    offsets = []
    total = 0
    for row in rows:
        offsets.append(total)
        total += len(row)

    edits: list[tuple[int, int, str]] = []
    depth = 0
    suite_colon = False
    tokens = tokenize.generate_tokens(io.StringIO(source).readline)
    for item in tokens:
        if item.type == tokenize.NEWLINE:
            suite_colon = False
            continue
        if item.type != tokenize.OP:
            continue
        if item.string in "([{":
            depth += 1
        elif item.string in ")]}" and depth:
            depth -= 1
        elif item.string == ":" and depth == 0:
            suite_colon = True

        line = item.start[0]
        start = offsets[line - 1] + item.start[1]
        end = offsets[line - 1] + item.end[1]
        if item.string == ",":
            row = rows[line - 1]
            next_column = item.end[1]
            if next_column >= len(row):
                continue
            following = row[next_column]
            if not following.isspace() and following not in ")]}":
                edits.append((end, end, " "))
        elif item.string == ";" and depth == 0 and not suite_colon:
            row = rows[line - 1]
            indentation = row[: len(row) - len(row.lstrip(" \t"))]
            newline = "\r\n" if row.endswith("\r\n") else "\n"
            # Consume horizontal whitespace after the separator. Keeping it
            # would add one extra indentation column on the expanded line.
            while end < offsets[line - 1] + len(row):
                character = source[end]
                if character not in " \t":
                    break
                end += 1
            edits.append((start, end, newline + indentation))

    rewritten = source
    for start, end, replacement in reversed(edits):
        rewritten = rewritten[:start] + replacement + rewritten[end:]
    return rewritten


def rewrite_file(path: Path, apply: bool) -> bool:
    """Check or rewrite one UTF-8 Python file and report whether it changed."""

    raw = path.read_bytes()
    has_bom = raw.startswith(b"\xef\xbb\xbf")
    source = raw.decode("utf-8-sig")
    rewritten = rewrite_source(source)
    changed = rewritten != source
    if changed and apply:
        encoded = rewritten.encode("utf-8")
        path.write_bytes((b"\xef\xbb\xbf" if has_bom else b"") + encoded)
    return changed


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser for check and apply modes."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--source-root",
        type=Path,
        default=Path("emtaint"),
        help="Package tree containing Python files",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Write changes; default mode only lists files",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """List or apply conservative rewrites and return whether work remains."""

    args = build_parser().parse_args(argv)
    paths = tuple(sorted(args.source_root.rglob("*.py")))
    changed = [path for path in paths if rewrite_file(path, args.apply)]
    for path in changed:
        print(path.as_posix())
    print(
        "mode="
        + ("apply" if args.apply else "check")
        + " files="
        + str(len(paths))
        + " changed="
        + str(len(changed))
    )
    return 0 if args.apply or not changed else 1


if __name__ == "__main__":
    raise SystemExit(main())
