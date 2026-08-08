"""Compare reviewer capability summaries against an explicit baseline report.

The comparison is intentionally additive. It never chooses what counts as an
accepted release and never changes findings, risk, classification, or
enforcement. Consumers opt in with ``--baseline-report`` and own the lifecycle
of that baseline artifact.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Callable, Sequence
from urllib.parse import urlparse

import reviewer_evidence_provenance as provenance

REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION = "1"
_SUPPORTED_CAPABILITY_SCHEMA_VERSION = "1"
_MAX_CHANGE_EVIDENCE = 5

log = logging.getLogger("audit_plugins")

_ACTIVE_BASELINES: dict[str, dict[str, Any]] | None = None


def _value(item: object, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _normalise_repository(value: object) -> str:
    raw = str(value or "").strip().rstrip("/")
    if not raw:
        return ""
    parsed = urlparse(raw if "://" in raw else f"https://github.com/{raw}")
    if parsed.hostname and parsed.hostname.casefold() != "github.com":
        return raw.casefold().removesuffix(".git")
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) >= 2:
        return f"github.com/{parts[0].casefold()}/{parts[1].casefold().removesuffix('.git')}"
    return raw.casefold().removesuffix(".git")


def _safe_text(value: object) -> str:
    return provenance._redact(value)


def _safe_int(value: object) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def _identity(report: object) -> dict[str, Any]:
    return {
        "repository": _safe_text(_value(report, "repository", "")),
        "release": _safe_text(_value(report, "release", "")),
        "artifact_sha256": _safe_text(_value(report, "artifact_sha256", "")),
        "source_commit": _safe_text(_value(report, "source_commit", "")),
        "final_classification": _safe_text(_value(report, "final_classification", "")),
        "risk_score": _safe_int(_value(report, "risk_score", 0)),
        "reviewer_capabilities_schema_version": _safe_text(
            _value(report, "reviewer_capabilities_schema_version", "")
        ),
    }


def _reports_from_payload(payload: object) -> list[dict[str, Any]]:
    if not isinstance(payload, dict):
        raise ValueError("baseline report must be a JSON object")
    if "reports" in payload:
        reports = payload.get("reports")
        if not isinstance(reports, list):
            raise ValueError("baseline aggregate field 'reports' must be a list")
        if not all(isinstance(item, dict) for item in reports):
            raise ValueError("baseline aggregate contains a non-object report")
        return list(reports)
    if payload.get("repository"):
        return [payload]
    raise ValueError("baseline JSON must be an aggregate audit report or one plugin report")


def load_baseline_report(path: str) -> dict[str, dict[str, Any]]:
    """Load an explicit baseline audit artifact, indexed by normalized repository."""
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)

    indexed: dict[str, dict[str, Any]] = {}
    for report in _reports_from_payload(payload):
        key = _normalise_repository(report.get("repository"))
        if not key:
            raise ValueError("baseline report is missing a repository")
        if key in indexed:
            raise ValueError(
                f"baseline contains more than one report for repository {report.get('repository')!r}"
            )
        indexed[key] = report
    return indexed


def _capability_map(report: object) -> dict[str, dict[str, Any]]:
    capabilities = _value(report, "reviewer_capabilities", []) or []
    if not isinstance(capabilities, list):
        return {}
    return {
        str(item.get("id") or ""): item
        for item in capabilities
        if isinstance(item, dict) and item.get("id")
    }


def _network_destinations(capability: dict[str, Any]) -> set[str]:
    return {
        _safe_text(item.get("destination") or "")
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict)
        and item.get("kind") == "network_destination"
        and item.get("destination")
    }


def _native_binary_keys(capability: dict[str, Any]) -> set[str]:
    keys: set[str] = set()
    for item in list(capability.get("evidence") or []):
        if not isinstance(item, dict) or item.get("kind") != "native_binary":
            continue
        digest = _safe_text(item.get("sha256") or "")
        path = _safe_text(item.get("path") or "")
        key = f"sha256:{digest}" if digest else f"path:{path}"
        if digest or path:
            keys.add(key)
    return keys


def _source_diff_categories(capability: dict[str, Any]) -> set[str]:
    return {
        _safe_text(item.get("category") or "")
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict)
        and item.get("kind") == "source_artifact_diff"
        and item.get("category")
    }


def _rule_ids(capability: dict[str, Any]) -> set[str]:
    return {_safe_text(value) for value in list(capability.get("rule_ids") or []) if value}


def _status_change(previous: str, current: str) -> str:
    if previous == current:
        return "unchanged"
    if previous == "not_observed" and current == "observed":
        return "newly_observed"
    if previous == "observed" and current == "not_observed":
        return "no_longer_observed"
    if previous == "unknown" and current == "observed":
        return "now_observed_after_unknown"
    if previous == "unknown" and current == "not_observed":
        return "now_not_observed_after_unknown"
    if current == "unknown" and previous != "unknown":
        return "coverage_became_unknown"
    return "status_changed"


def _evidence_changes(
    capability_id: str,
    previous: dict[str, Any],
    current: dict[str, Any],
) -> tuple[list[str], dict[str, list[str]]]:
    kinds: list[str] = []
    details: dict[str, list[str]] = {}

    previous_rules, current_rules = _rule_ids(previous), _rule_ids(current)
    added_rules = sorted(current_rules - previous_rules)
    removed_rules = sorted(previous_rules - current_rules)
    if added_rules or removed_rules:
        kinds.append("rule_profile_changed")
        details["added_rule_ids"] = added_rules
        details["removed_rule_ids"] = removed_rules

    if capability_id == "network_communication":
        old, new = _network_destinations(previous), _network_destinations(current)
        added, removed = sorted(new - old), sorted(old - new)
        if added or removed:
            kinds.append("network_destinations_changed")
            details["added_destinations"] = added
            details["removed_destinations"] = removed

    if capability_id == "native_code":
        old, new = _native_binary_keys(previous), _native_binary_keys(current)
        added, removed = sorted(new - old), sorted(old - new)
        if added or removed:
            kinds.append("native_binaries_changed")
            details["added_native_binaries"] = added
            details["removed_native_binaries"] = removed

    if capability_id == "source_release_integrity":
        old, new = _source_diff_categories(previous), _source_diff_categories(current)
        added, removed = sorted(new - old), sorted(old - new)
        if added or removed:
            kinds.append("source_difference_profile_changed")
            details["added_source_difference_categories"] = added
            details["removed_source_difference_categories"] = removed

    return kinds, details


def _current_change_evidence(
    capability: dict[str, Any],
    status_change: str,
    evidence_changes: list[str],
    details: dict[str, list[str]],
) -> list[dict[str, Any]]:
    evidence = [
        item
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict)
    ]

    def relevant(item: dict[str, Any]) -> bool:
        if status_change in {"newly_observed", "now_observed_after_unknown"}:
            return True
        if (
            "network_destinations_changed" in evidence_changes
            and item.get("kind") == "network_destination"
            and item.get("destination") in set(details.get("added_destinations", []))
        ):
            return True
        if "native_binaries_changed" in evidence_changes and item.get("kind") == "native_binary":
            digest = str(item.get("sha256") or "")
            path = str(item.get("path") or "")
            key = f"sha256:{digest}" if digest else f"path:{path}"
            if key in set(details.get("added_native_binaries", [])):
                return True
        if (
            "source_difference_profile_changed" in evidence_changes
            and item.get("kind") == "source_artifact_diff"
            and item.get("category")
            in set(details.get("added_source_difference_categories", []))
        ):
            return True
        if (
            "rule_profile_changed" in evidence_changes
            and item.get("kind") == "finding"
            and item.get("rule_id") in set(details.get("added_rule_ids", []))
        ):
            return True
        return False

    return [dict(item) for item in evidence if relevant(item)][:_MAX_CHANGE_EVIDENCE]


def _summary(
    title: str,
    previous_status: str,
    current_status: str,
    status_change: str,
    evidence_changes: list[str],
    details: dict[str, list[str]],
) -> str:
    parts: list[str] = []
    if status_change != "unchanged":
        parts.append(f"{previous_status} → {current_status}")
    if "network_destinations_changed" in evidence_changes:
        parts.append(
            f"network destinations +{len(details.get('added_destinations', []))}"
            f"/-{len(details.get('removed_destinations', []))}"
        )
    if "native_binaries_changed" in evidence_changes:
        parts.append(
            f"native binaries +{len(details.get('added_native_binaries', []))}"
            f"/-{len(details.get('removed_native_binaries', []))}"
        )
    if "source_difference_profile_changed" in evidence_changes:
        parts.append("source/release difference profile changed")
    if "rule_profile_changed" in evidence_changes:
        parts.append(
            f"rule profile +{len(details.get('added_rule_ids', []))}"
            f"/-{len(details.get('removed_rule_ids', []))}"
        )
    return "; ".join(parts) if parts else f"{title} unchanged"


def compare_reviewer_capabilities(
    current_report: object,
    baseline_report: object | None,
) -> dict[str, Any]:
    """Compare one current report against one explicitly supplied baseline report."""
    current_identity = _identity(current_report)
    comparison: dict[str, Any] = {
        "status": "unavailable",
        "status_reason": "",
        "baseline": _identity(baseline_report or {}),
        "current": current_identity,
        "same_artifact": False,
        "changed_count": 0,
        "attention_count": 0,
        "capabilities": [],
    }

    if baseline_report is None:
        comparison["status"] = "baseline_not_found"
        comparison["status_reason"] = (
            "No baseline report matched this repository. No release comparison was inferred."
        )
        return comparison

    baseline_schema = str(
        _value(baseline_report, "reviewer_capabilities_schema_version", "") or ""
    )
    current_schema = str(
        _value(current_report, "reviewer_capabilities_schema_version", "") or ""
    )
    if not baseline_schema or not _capability_map(baseline_report):
        comparison["status"] = "baseline_capabilities_unavailable"
        comparison["status_reason"] = (
            "The baseline report predates reviewer capability summaries or does not contain them."
        )
        return comparison
    if baseline_schema != _SUPPORTED_CAPABILITY_SCHEMA_VERSION:
        comparison["status"] = "baseline_schema_unsupported"
        comparison["status_reason"] = (
            f"Baseline reviewer capability schema {baseline_schema!r} is not supported."
        )
        return comparison
    if current_schema != _SUPPORTED_CAPABILITY_SCHEMA_VERSION:
        comparison["status"] = "current_schema_unsupported"
        comparison["status_reason"] = (
            f"Current reviewer capability schema {current_schema!r} is not supported."
        )
        return comparison

    previous_caps = _capability_map(baseline_report)
    current_caps = _capability_map(current_report)
    if set(previous_caps) != set(current_caps):
        comparison["status"] = "capability_set_mismatch"
        comparison["status_reason"] = (
            "Baseline and current reports do not expose the same capability identifiers."
        )
        return comparison

    valid_statuses = {"observed", "not_observed", "unknown"}
    for capability_id in current_caps:
        previous_status = _safe_text(previous_caps[capability_id].get("status") or "")
        current_status = _safe_text(current_caps[capability_id].get("status") or "")
        if previous_status not in valid_statuses or current_status not in valid_statuses:
            comparison["status"] = "capability_status_invalid"
            comparison["status_reason"] = (
                f"Capability {capability_id!r} contains an unsupported status value."
            )
            return comparison

    baseline_identity = comparison["baseline"]
    comparison["same_artifact"] = bool(
        baseline_identity.get("artifact_sha256")
        and baseline_identity.get("artifact_sha256")
        == current_identity.get("artifact_sha256")
    )
    changes: list[dict[str, Any]] = []
    for capability_id, current in current_caps.items():
        previous = previous_caps[capability_id]
        previous_status = _safe_text(previous.get("status") or "unknown")
        current_status = _safe_text(current.get("status") or "unknown")
        transition = _status_change(previous_status, current_status)
        evidence_change_types, details = _evidence_changes(
            capability_id, previous, current
        )
        changed = transition != "unchanged" or bool(evidence_change_types)
        item = {
            "id": capability_id,
            "title": _safe_text(current.get("title") or previous.get("title") or capability_id),
            "question": _safe_text(current.get("question") or previous.get("question") or ""),
            "baseline_status": previous_status,
            "current_status": current_status,
            "status_change": transition,
            "evidence_changes": evidence_change_types,
            "changed": changed,
            "reviewer_attention": changed,
            "summary": _summary(
                str(current.get("title") or capability_id),
                previous_status,
                current_status,
                transition,
                evidence_change_types,
                details,
            ),
            "baseline_evidence_count": _safe_int(previous.get("evidence_count")),
            "current_evidence_count": _safe_int(current.get("evidence_count")),
            "details": details,
            "current_change_evidence": _current_change_evidence(
                current, transition, evidence_change_types, details
            ),
        }
        changes.append(item)

    comparison["status"] = "compared"
    comparison["status_reason"] = "Reviewer capability schemas are compatible."
    comparison["capabilities"] = changes
    comparison["changed_count"] = sum(1 for item in changes if item["changed"])
    comparison["attention_count"] = sum(
        1 for item in changes if item["reviewer_attention"]
    )
    return comparison


def _render_identity(identity: dict[str, Any]) -> str:
    release = provenance._code(identity.get("release") or "not recorded")
    artifact = provenance._code(identity.get("artifact_sha256") or "not recorded")
    commit = provenance._code(identity.get("source_commit") or "not recorded")
    classification = provenance._code(
        identity.get("final_classification") or "not recorded"
    )
    return (
        f"release {release}; artifact {artifact}; source {commit}; "
        f"classification {classification}"
    )


def render_reviewer_capability_comparison(comparison: dict[str, Any]) -> str:
    """Render a reviewer-first Markdown delta without overstating baseline trust."""
    lines = ["## Capability Changes Against Baseline", ""]
    status = str(comparison.get("status") or "unavailable")
    if status != "compared":
        lines.extend(
            [
                f"> **Comparison unavailable:** {provenance._md(comparison.get('status_reason') or status)}",
                "",
                "No previous-release behavior was inferred from missing or incompatible data.",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            f"- Baseline: {_render_identity(dict(comparison.get('baseline') or {}))}",
            f"- Current: {_render_identity(dict(comparison.get('current') or {}))}",
            f"- Same artifact: {provenance._code('yes' if comparison.get('same_artifact') else 'no')}",
            "",
        ]
    )

    changed = [
        item
        for item in list(comparison.get("capabilities") or [])
        if isinstance(item, dict) and item.get("changed")
    ]
    if not changed:
        lines.append("No reviewer capability or tracked evidence-profile changes were detected.")
        return "\n".join(lines)

    lines.extend(
        [
            "| Capability | Baseline | Current | Change |",
            "|---|---|---|---|",
        ]
    )
    for item in changed:
        lines.append(
            f"| {provenance._md(item.get('title') or item.get('id'))} | "
            f"{provenance._code(item.get('baseline_status') or 'unknown')} | "
            f"{provenance._code(item.get('current_status') or 'unknown')} | "
            f"{provenance._md(item.get('summary') or 'changed')} |"
        )

    for item in changed:
        evidence = list(item.get("current_change_evidence") or [])
        details = dict(item.get("details") or {})
        lines.extend(["", f"### {provenance._md(item.get('title') or item.get('id'))}", ""])
        lines.append(provenance._md(item.get("summary") or "changed") + ".")
        for key in (
            "added_destinations",
            "removed_destinations",
            "added_native_binaries",
            "removed_native_binaries",
            "added_source_difference_categories",
            "removed_source_difference_categories",
            "added_rule_ids",
            "removed_rule_ids",
        ):
            values = list(details.get(key) or [])
            if values:
                label = key.replace("_", " ")
                rendered = ", ".join(provenance._code(value) for value in values)
                lines.append(f"- {provenance._md(label.capitalize())}: {rendered}")
        if evidence:
            lines.append("- Current evidence:")
            for evidence_item in evidence:
                lines.append(f"  - {provenance._render_evidence(evidence_item)}")
    return "\n".join(lines).rstrip()


def _insert_comparison(markdown: str, section: str) -> str:
    marker = "## Reviewer Capability Summary"
    if marker not in markdown:
        return f"{section}\n\n{markdown}"
    return markdown.replace(marker, f"{section}\n\n{marker}", 1)


def _extract_baseline_option(argv: Sequence[str]) -> tuple[list[str], str | None]:
    stripped: list[str] = []
    baseline_path: str | None = None
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--baseline-report":
            if baseline_path is not None:
                raise ValueError("--baseline-report may only be supplied once")
            if index + 1 >= len(argv):
                raise ValueError("--baseline-report requires a path")
            baseline_path = argv[index + 1]
            index += 2
            continue
        if arg.startswith("--baseline-report="):
            if baseline_path is not None:
                raise ValueError("--baseline-report may only be supplied once")
            baseline_path = arg.split("=", 1)[1]
            if not baseline_path:
                raise ValueError("--baseline-report requires a path")
            index += 1
            continue
        stripped.append(arg)
        index += 1
    return stripped, baseline_path


def install(core: object) -> object:
    """Install opt-in baseline comparison on the active audit core."""
    if getattr(core, "_reviewer_capability_comparison_installed", False):
        return core
    if not getattr(core, "_reviewer_capabilities_installed", False):
        raise RuntimeError("reviewer_capabilities must be installed first")
    if not getattr(core, "_reviewer_evidence_provenance_installed", False):
        raise RuntimeError("reviewer_evidence_provenance must be installed first")

    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_report_to_dict: Callable[[Any], dict[str, Any]] = core._report_to_dict
    raw_generate_markdown: Callable[[Any], str] = core.generate_markdown_report
    raw_main: Callable[[Sequence[str] | None], int] = core.main

    def audit_repository(*args: Any, **kwargs: Any) -> Any:
        report = raw_audit_repository(*args, **kwargs)
        baselines = _ACTIVE_BASELINES
        if baselines is not None:
            key = _normalise_repository(_value(report, "repository", ""))
            baseline = baselines.get(key)
            report.reviewer_capability_comparison_schema_version = (
                REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION
            )
            report.reviewer_capability_comparison = compare_reviewer_capabilities(
                report, baseline
            )
        return report

    def report_to_dict(report: Any) -> dict[str, Any]:
        payload = raw_report_to_dict(report)
        comparison = getattr(report, "reviewer_capability_comparison", None)
        if comparison is not None:
            payload["reviewer_capability_comparison_schema_version"] = (
                REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION
            )
            payload["reviewer_capability_comparison"] = comparison
        return payload

    def generate_markdown_report(report: Any) -> str:
        rendered = raw_generate_markdown(report)
        comparison = getattr(report, "reviewer_capability_comparison", None)
        if comparison is None:
            return rendered
        return _insert_comparison(
            rendered, render_reviewer_capability_comparison(comparison)
        )

    def main(argv: Sequence[str] | None = None) -> int:
        import sys

        resolved = list(argv) if argv is not None else list(sys.argv[1:])
        try:
            stripped, baseline_path = _extract_baseline_option(resolved)
            baselines = (
                load_baseline_report(os.path.abspath(baseline_path))
                if baseline_path is not None
                else None
            )
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            log.error("Invalid --baseline-report: %s", exc)
            return 2

        global _ACTIVE_BASELINES
        previous = _ACTIVE_BASELINES
        _ACTIVE_BASELINES = baselines
        try:
            return int(raw_main(stripped))
        finally:
            _ACTIVE_BASELINES = previous

    core.audit_repository = audit_repository
    core._report_to_dict = report_to_dict
    core.generate_markdown_report = generate_markdown_report
    core.main = main
    core.compare_reviewer_capabilities = compare_reviewer_capabilities
    core.render_reviewer_capability_comparison = render_reviewer_capability_comparison
    core.load_baseline_report = load_baseline_report
    core.REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION = (
        REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION
    )
    core._reviewer_capability_comparison_installed = True
    return core
