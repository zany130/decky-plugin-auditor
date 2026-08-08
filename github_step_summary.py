"""Keep GitHub Actions summaries useful and below the platform size limit.

The full Markdown report remains unchanged on disk. This layer only controls
what the auditor writes to ``GITHUB_STEP_SUMMARY``: detailed output is preserved
for small runs, while large runs fall back to a compact reviewer-oriented index.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from pathlib import Path
from types import ModuleType
from typing import Any, Callable

# GitHub currently rejects a job summary above 1 MiB. Leave generous headroom
# for anything another step may append to the same summary file.
SUMMARY_SOFT_LIMIT_BYTES = 900_000
MAX_CHANGE_SECTIONS = 200

_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b"),
)


def _safe_text(value: object) -> str:
    text = "" if value is None else str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    text = " ".join(text.splitlines())
    for char in ("\\", "`", "*", "_", "~", "[", "]", "(", ")", "<", ">", "|"):
        text = text.replace(char, f"\\{char}")
    return text


def _classification_counts(reports: list[dict[str, Any]]) -> str:
    order = ("AUDIT_ERROR", "BLOCK", "MANUAL_REVIEW", "PASS_WITH_WARNINGS", "PASS")
    counts = {name: 0 for name in order}
    for report in reports:
        value = str(report.get("final_classification") or "")
        counts[value] = counts.get(value, 0) + 1
    return " · ".join(f"{name}: {counts.get(name, 0)}" for name in order)


def _baseline_cell(report: dict[str, Any]) -> str:
    comparison = report.get("reviewer_capability_comparison")
    if not isinstance(comparison, dict):
        return "not requested"
    status = str(comparison.get("status") or "")
    if status == "compared":
        changed = int(comparison.get("changed_count") or 0)
        attention = int(comparison.get("attention_count") or 0)
        same = "same artifact" if comparison.get("same_artifact") else "different artifact"
        return f"{changed} changed / {attention} attention ({same})"
    if status == "baseline_not_found":
        return "baseline unavailable"
    return status or "comparison unavailable"


def _header(reports: list[dict[str, Any]], note: str) -> list[str]:
    return [
        "## Security Audit Summary",
        "",
        f"Audited **{len(reports)}** plugin repository/repositories.",
        "",
        _classification_counts(reports),
        "",
        note,
        "",
    ]


def _minimal_index(reports: list[dict[str, Any]]) -> str:
    """Try a second, smaller all-repository index before header-only fallback."""
    lines = _header(
        reports,
        "The complete per-plugin evidence remains in `security-report.md`. "
        "This reduced index is used because the richer compact summary was still too large.",
    )
    lines.extend(
        [
            "| Repository | Classification | Accepted-baseline comparison |",
            "| --- | --- | --- |",
        ]
    )
    for report in reports:
        lines.append(
            "| "
            + " | ".join(
                [
                    _safe_text(report.get("repository")),
                    _safe_text(report.get("final_classification")),
                    _safe_text(_baseline_cell(report)),
                ]
            )
            + " |"
        )
    rendered = "\n".join(lines).rstrip() + "\n"
    if len(rendered.encode("utf-8")) <= SUMMARY_SOFT_LIMIT_BYTES:
        return rendered
    return (
        "## Security Audit Summary\n\n"
        f"Audited **{len(reports)}** plugin repository/repositories.\n\n"
        f"{_classification_counts(reports)}\n\n"
        "Even the reduced per-repository index exceeded the configured safety limit. "
        "See `security-report.md` for complete details.\n"
    )


def compact_summary(payload: object) -> str:
    """Render a bounded, reviewer-oriented summary from serialized audit JSON."""
    if not isinstance(payload, dict):
        raise ValueError("audit summary payload must be an object")
    raw_reports = payload.get("reports")
    if not isinstance(raw_reports, list):
        raise ValueError("audit summary payload must contain reports")
    reports = [item for item in raw_reports if isinstance(item, dict)]

    lines = _header(
        reports,
        "The complete per-plugin evidence remains in the generated `security-report.md` report. "
        "This compact view is used because the detailed report is too large for GitHub's job-summary limit.",
    )
    lines.extend(
        [
            "| Repository | Release | Classification | Risk | Accepted-baseline comparison |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )

    for report in reports:
        lines.append(
            "| "
            + " | ".join(
                [
                    _safe_text(report.get("repository")),
                    _safe_text(report.get("release")),
                    _safe_text(report.get("final_classification")),
                    str(int(report.get("risk_score") or 0)),
                    _safe_text(_baseline_cell(report)),
                ]
            )
            + " |"
        )

    attention_reports: list[dict[str, Any]] = []
    for report in reports:
        comparison = report.get("reviewer_capability_comparison")
        if isinstance(comparison, dict) and int(comparison.get("attention_count") or 0) > 0:
            attention_reports.append(report)

    if attention_reports:
        lines.extend(["", "### Security-relevant baseline changes", ""])
        rendered = 0
        for report in attention_reports:
            if rendered >= MAX_CHANGE_SECTIONS:
                break
            comparison = report.get("reviewer_capability_comparison") or {}
            lines.append(
                f"#### {_safe_text(report.get('repository'))} — {_safe_text(report.get('release'))}"
            )
            if comparison.get("same_artifact"):
                lines.append(
                    "_The artifact SHA-256 is unchanged; differences may reflect audit coverage or analysis changes rather than plugin bytes._"
                )
            changed = [
                item
                for item in comparison.get("capabilities") or []
                if isinstance(item, dict) and item.get("reviewer_attention")
            ]
            if not changed:
                lines.append("- Comparison needs reviewer attention; see the full report for details.")
            else:
                for item in changed:
                    lines.append(
                        f"- **{_safe_text(item.get('title') or item.get('id'))}:** "
                        f"{_safe_text(item.get('summary') or item.get('status_change'))}"
                    )
            lines.append("")
            rendered += 1

        if len(attention_reports) > rendered:
            lines.append(
                f"_{len(attention_reports) - rendered} additional comparison section(s) omitted from the job summary; see the full report._"
            )

    result = "\n".join(lines).rstrip() + "\n"
    if len(result.encode("utf-8")) > SUMMARY_SOFT_LIMIT_BYTES:
        return _minimal_index(reports)
    return result


def _output_dir(core: ModuleType, argv: object) -> Path:
    tokens = list(argv) if argv is not None else list(__import__("sys").argv[1:])
    for index, token in enumerate(tokens):
        if token == "--output-dir" and index + 1 < len(tokens):
            return Path(str(tokens[index + 1]))
        if isinstance(token, str) and token.startswith("--output-dir="):
            return Path(token.split("=", 1)[1])
    return Path(str(getattr(core, "DEFAULT_OUTPUT_DIR", "security-reports")))


def _write_selected_summary(
    actual_summary: str,
    detailed_summary: Path,
    report_json: Path,
) -> None:
    try:
        detailed = detailed_summary.read_text(encoding="utf-8")
    except OSError:
        detailed = ""

    if detailed and len(detailed.encode("utf-8")) <= SUMMARY_SOFT_LIMIT_BYTES:
        selected = detailed
    else:
        try:
            with open(report_json, encoding="utf-8") as handle:
                selected = compact_summary(json.load(handle))
        except Exception:
            selected = (
                "## Security Audit Summary\n\n"
                "A bounded GitHub job summary could not be rendered from the generated audit output. "
                "See the report artifact and job logs for complete details.\n"
            )

    try:
        with open(actual_summary, "a", encoding="utf-8") as handle:
            handle.write(selected)
    except OSError:
        # Summary rendering must never change audit classification or exit code.
        pass


def install(core: ModuleType) -> ModuleType:
    """Wrap ``core.main`` so detailed reports cannot overflow job summaries."""
    if getattr(core, "_github_step_summary_installed", False):
        return core

    original_main: Callable[..., int] = core.main

    def bounded_main(argv: object = None) -> int:
        actual_summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if not actual_summary:
            return original_main(argv)

        fd, temp_name = tempfile.mkstemp(prefix="decky-audit-summary-", suffix=".md")
        os.close(fd)
        temp_path = Path(temp_name)
        os.environ["GITHUB_STEP_SUMMARY"] = str(temp_path)
        try:
            result = original_main(argv)
        finally:
            os.environ["GITHUB_STEP_SUMMARY"] = actual_summary
            try:
                report_json = _output_dir(core, argv) / "security-report.json"
                _write_selected_summary(actual_summary, temp_path, report_json)
            except Exception:
                # Never mask the audit's own return value or exception with
                # non-critical summary rendering behavior.
                pass
            finally:
                try:
                    temp_path.unlink()
                except OSError:
                    pass
        return result

    core.main = bounded_main
    core._github_step_summary_installed = True
    return core
