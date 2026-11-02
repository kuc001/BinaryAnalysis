"""Tests for conservative token-aware readability rewrites."""

import unittest

from scripts.readability_rewrite import rewrite_source


class ReadabilityRewriteTests(unittest.TestCase):
    """Protect source semantics while expanding compact legacy formatting."""

    def test_adds_argument_spacing_without_touching_strings_or_comments(self) -> None:
        source = "call(left,right)  # keep,a\ntext = 'keep,a'\n"
        self.assertEqual(
            rewrite_source(source),
            "call(left, right)  # keep,a\ntext = 'keep,a'\n",
        )

    def test_expands_simple_semicolon_statements_with_current_indent(self) -> None:
        source = "def run():\n    left=1; right=2\n"
        self.assertEqual(
            rewrite_source(source),
            "def run():\n    left=1\n    right=2\n",
        )

    def test_keeps_one_line_suite_for_manual_rewrite(self) -> None:
        source = "if ready: first();second()\n"
        self.assertEqual(rewrite_source(source), source)


if __name__ == "__main__":
    unittest.main()
