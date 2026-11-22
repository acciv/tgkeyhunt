"""Tests for the offline tgkeyhunt Markdown report contract.

All token-like strings below are deliberately fake and contain ``FAKE``.
"""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO

from tgkeyhunt.report import assert_no_secret, load_report, main, render_markdown

# 36 characters from the allowed secret alphabet; not a real token.
FAKE_SECRET = "FAKE" * 9
FAKE_TOKEN = "123456789:" + FAKE_SECRET


def sample_report():
    """Return a report with one finding per confidence level."""
    return {
        "scanned_files": 2,
        "skipped_files": 1,
        "findings": [
            {
                "file": "examples/fixtures/app.log",
                "line": 7,
                "column": 3,
                "bot_id": "123456789",
                "secret_length": 36,
                "entropy": 4.21,
                "confidence": "high",
                "reason": "exact length and high entropy",
            },
            {
                "file": "examples/fixtures/config.py",
                "line": 12,
                "column": 1,
                "bot_id": "987654321",
                "secret_length": 32,
                "entropy": 3.72,
                "confidence": "medium",
                "reason": "token-like length and entropy",
            },
            {
                "file": "examples/fixtures/notes.txt",
                "line": 2,
                "column": 1,
                "bot_id": "555555555",
                "secret_length": 28,
                "entropy": 2.5,
                "confidence": "low",
                "reason": "weak entropy or unusual length",
            },
        ],
    }


class RenderMarkdownTests(unittest.TestCase):
    def setUp(self):
        self.markdown = render_markdown(sample_report())

    def test_heading_and_sections(self):
        self.assertTrue(self.markdown.startswith("# tgkeyhunt report\n"))
        for section in ("## Summary", "## Findings", "## Recommendations"):
            self.assertIn(section, self.markdown)

    def test_summary_table(self):
        for row in (
            "| Metric | Value |",
            "| scanned_files | 2 |",
            "| skipped_files | 1 |",
            "| total findings | 3 |",
        ):
            self.assertIn(row, self.markdown)

    def test_findings_table_rows(self):
        self.assertIn(
            "| File | Line | Confidence | Bot ID | Entropy | Reason |",
            self.markdown,
        )
        for file_name, line, bot_id in (
            ("examples/fixtures/app.log", "7", "123456789"),
            ("examples/fixtures/config.py", "12", "987654321"),
            ("examples/fixtures/notes.txt", "2", "555555555"),
        ):
            row = "| {} | {} |".format(file_name, line)
            self.assertIn(row, self.markdown)
            self.assertIn(bot_id, self.markdown)
        self.assertEqual(self.markdown.count("| examples/fixtures/"), 3)

    def test_confidence_counts(self):
        for row in ("| high | 1 |", "| medium | 1 |", "| low | 1 |"):
            self.assertIn(row, self.markdown)

    def test_recommendations_are_concrete(self):
        recommendations = self.markdown.split("## Recommendations", 1)[1]
        for keyword in ("rotate", "revoke", "remove", "secret manager", "ci"):
            self.assertIn(keyword, recommendations.lower())

    def test_fake_key_note(self):
        self.assertIn("fake", self.markdown.lower())
        self.assertIn("FAKE", self.markdown)

    def test_no_secret_leak_from_injected_fields(self):
        clean = sample_report()["findings"][0]
        poisoned = dict(
            clean,
            reason="see " + FAKE_TOKEN,
            secret=FAKE_SECRET,
            token=FAKE_TOKEN,
            note="ignored " + FAKE_TOKEN,
        )
        second = dict(clean, file="examples/fixtures/second.log", line=8, column=1)
        markdown = render_markdown(
            {
                "scanned_files": 1,
                "skipped_files": 0,
                "findings": [poisoned, second],
            }
        )

        self.assertNotIn(FAKE_SECRET, markdown)
        self.assertNotIn(FAKE_TOKEN, markdown)
        self.assertIn("[REDACTED]", markdown)
        self.assertIn("examples/fixtures/second.log", markdown)

    def test_assert_no_secret_helper(self):
        self.assertIsNone(assert_no_secret(sample_report()["findings"][0]))
        poisoned = dict(sample_report()["findings"][0], secret=FAKE_SECRET)
        with self.assertRaises(ValueError):
            assert_no_secret(poisoned)
        with self.assertRaises(ValueError):
            assert_no_secret(dict(sample_report()["findings"][0], note=FAKE_TOKEN))


class LoadReportAndCliTests(unittest.TestCase):
    def test_load_report_reads_json(self):
        report = sample_report()
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "findings.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(report, handle)
            self.assertEqual(load_report(path), report)

    def test_cli_writes_file_and_prints_status(self):
        report = sample_report()
        with tempfile.TemporaryDirectory() as directory:
            findings_path = os.path.join(directory, "findings.json")
            output_path = os.path.join(directory, "report.md")
            with open(findings_path, "w", encoding="utf-8") as handle:
                json.dump(report, handle)

            stdout = StringIO()
            with redirect_stdout(stdout):
                status = main([findings_path, output_path])

            self.assertEqual(status, 0)
            self.assertTrue(os.path.isfile(output_path))
            with open(output_path, "r", encoding="utf-8") as handle:
                written = handle.read()
            self.assertEqual(written, render_markdown(load_report(findings_path)))
            self.assertIn("Wrote", stdout.getvalue())
            self.assertIn(output_path, stdout.getvalue())


if __name__ == "__main__":
    unittest.main()
