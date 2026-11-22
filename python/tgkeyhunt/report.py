"""Render a tgkeyhunt ``findings.json`` file as a safe Markdown report.

Only an allow-list of fields is rendered and every rendered value is passed
through a redaction filter, so a complete ``bot_id:secret`` value can never
appear in the report. The module uses only the Python standard library and
never accesses the network.
"""

from __future__ import annotations

import argparse
import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

__all__ = ["load_report", "render_markdown", "assert_no_secret", "main"]

# A candidate token as defined by SPEC.md: 6-12 digit id, 30-50 character
# secret from [A-Za-z0-9_-], with token-character boundaries on both sides.
_TOKEN_RE = re.compile(
    r"(?<![A-Za-z0-9_-])\d{6,12}:[A-Za-z0-9_-]{30,50}(?![A-Za-z0-9_-])"
)

# Field names that must never be trusted as report content.
_SECRET_FIELDS = frozenset(
    {
        "secret",
        "token",
        "bot_token",
        "api_key",
        "apikey",
        "key",
        "password",
        "authorization",
        "auth",
        "credential",
        "credentials",
    }
)

_REDACTED = "[REDACTED]"
_CONFIDENCES: Tuple[str, ...] = ("high", "medium", "low")

_RECOMMENDATIONS: Tuple[str, ...] = (
    "Rotate and replace every real bot token that appeared in a finding; treat it as compromised.",
    "Revoke the exposed token with BotFather and issue a fresh one before re-enabling the bot.",
    "Remove the token from source files, logs and chat history; purge copies from backups and build artifacts.",
    "Store secrets in environment variables or a secret manager, never in committed files.",
    "Add automated scanning (for example tgkeyhunt in pre-commit and CI) to block future leaks.",
    "Limit the bot's permissions and review recent API activity for signs of abuse.",
)


def load_report(path: str) -> Dict[str, Any]:
    """Read and parse a tgkeyhunt ``findings.json`` file.

    Args:
        path: Path to the JSON report produced by a tgkeyhunt scanner.

    Returns:
        The parsed report as a dictionary.

    Raises:
        ValueError: If the top-level JSON value is not an object.
    """
    with open(path, "r", encoding="utf-8") as handle:
        report = json.load(handle)
    if not isinstance(report, dict):
        raise ValueError("findings.json must contain a JSON object")
    return report


def assert_no_secret(finding: Dict[str, Any]) -> None:
    """Assert that a finding has no ``bot_id:secret`` shape.

    A well-formed finding stores only the bot id, the secret *length* and its
    entropy. This strict guard raises ``ValueError`` when a finding carries an
    obvious secret field or any string value containing a complete token.

    ``render_markdown`` does not depend on this check: it redacts defensively
    even when a caller supplies an unvalidated finding.

    Raises:
        ValueError: If *finding* is not a dict or contains secret material.
    """
    if not isinstance(finding, dict):
        raise ValueError("finding must be a dict")

    for name in _SECRET_FIELDS:
        if name in finding:
            raise ValueError("finding contains forbidden field {!r}".format(name))

    for value in finding.values():
        if isinstance(value, str) and _TOKEN_RE.search(value):
            raise ValueError("finding contains a bot_id:secret shaped value")


def _redact(value: Any) -> str:
    """Convert a value to text and replace any token-shaped substring."""
    text = "" if value is None else str(value)
    return _TOKEN_RE.sub(_REDACTED, text)


def _cell(value: Any) -> str:
    """Return a redacted, Markdown-table-safe cell."""
    return _redact(value).replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def _as_int(value: Any, default: int = 0) -> int:
    """Best-effort integer conversion used for counters and sorting."""
    if isinstance(value, bool):
        return default
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _confidence(value: Any) -> str:
    """Normalise a confidence value to one of the three documented levels."""
    if isinstance(value, str) and value.strip().lower() in _CONFIDENCES:
        return value.strip().lower()
    return "low"


def _bot_id(value: Any) -> str:
    """Render only a plausible bot id; redact anything else."""
    text = _redact(value)
    if re.fullmatch(r"\d{6,12}", text):
        return text
    return _REDACTED if text else "-"


def _entropy(value: Any) -> str:
    """Format entropy to two decimals, or redact an unusable value."""
    if isinstance(value, bool) or value is None:
        return "-"
    try:
        return "{:.2f}".format(float(value))
    except (TypeError, ValueError):
        return _cell(value) or "-"


def _sort_key(finding: Dict[str, Any]) -> Tuple[str, int, int]:
    """Sort findings by file, then line, then column (as SPEC.md requires)."""
    return (
        str(finding.get("file", "")),
        _as_int(finding.get("line"), 10**9),
        _as_int(finding.get("column"), 10**9),
    )


def _findings(report: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return the report's findings as a deterministically ordered list."""
    raw = report.get("findings", [])
    if not isinstance(raw, list):
        return []
    return sorted((item for item in raw if isinstance(item, dict)), key=_sort_key)


def render_markdown(report: Dict[str, Any]) -> str:
    """Render *report* as a Markdown report without leaking any secret.

    The output contains a Summary table (file counters, total findings and
    confidence counts), a Findings table with the six documented columns, a
    Recommendations section and an explicit fake-key/redaction note.
    """
    if not isinstance(report, dict):
        raise ValueError("report must be a dict")

    findings = _findings(report)
    counts = {level: 0 for level in _CONFIDENCES}
    for finding in findings:
        counts[_confidence(finding.get("confidence"))] += 1

    lines: List[str] = [
        "# tgkeyhunt report",
        "",
        "## Summary",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        "| scanned_files | {} |".format(_as_int(report.get("scanned_files"))),
        "| skipped_files | {} |".format(_as_int(report.get("skipped_files"))),
        "| total findings | {} |".format(len(findings)),
    ]
    for level in _CONFIDENCES:
        lines.append("| {} | {} |".format(level, counts[level]))

    lines.extend(
        [
            "",
            "## Findings",
            "",
            "| File | Line | Confidence | Bot ID | Entropy | Reason |",
            "| --- | --- | --- | --- | --- | --- |",
        ]
    )
    for finding in findings:
        lines.append(
            "| {} | {} | {} | {} | {} | {} |".format(
                _cell(finding.get("file", "-")),
                _cell(finding.get("line", "-")),
                _confidence(finding.get("confidence")),
                _bot_id(finding.get("bot_id")),
                _entropy(finding.get("entropy")),
                _cell(finding.get("reason", "-")),
            )
        )

    lines.extend(["", "## Recommendations", ""])
    lines.extend("- {}".format(step) for step in _RECOMMENDATIONS)

    lines.extend(
        [
            "",
            "> Note: all keys in examples are fake; every example token contains `FAKE`.",
            "> No complete secret values are included in this report. Any token-like",
            "> `bot_id:secret` material is redacted as `{}`.".format(_REDACTED),
            "",
        ]
    )
    return "\n".join(lines)


def main(argv: Optional[Sequence[str]] = None) -> int:
    """CLI entry point: ``python -m tgkeyhunt.report findings.json report.md``."""
    parser = argparse.ArgumentParser(
        prog="python -m tgkeyhunt.report",
        description="Render a tgkeyhunt findings.json file as a safe Markdown report.",
    )
    parser.add_argument("findings", help="path to the input findings.json")
    parser.add_argument("output", help="path of the Markdown report to write")
    args = parser.parse_args(argv)

    report = load_report(args.findings)
    with open(args.output, "w", encoding="utf-8") as handle:
        handle.write(render_markdown(report))
    print("Wrote {} ({} findings)".format(args.output, len(_findings(report))))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
