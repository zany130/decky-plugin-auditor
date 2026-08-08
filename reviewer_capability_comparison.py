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
_MAX_BASELINE_BYTES = 64 * 1024 * 1024
_MAX_BASELINE_REPORTS = 10_000
_MISSING = object()
_SOURCE_DIFF_CATEGORIES = (
    "zip_only_executables",
    "zip_only_scripts",
    "large_binaries_absent_from_source",
    "unexpected_urls",
    "same_path_modified",
    "grouped_packaged_outputs",
    "generated_or_dependency_differences",
    "other_same_path_differences",
    "expected_build_stamp_differences",
)

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
        return (
            f"github.com/{parts[0].casefold()}/"
            f"{parts[1].casefold().removesuffix('.git')}"
        )
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
        "final_classification": _safe_text(
            _value(report, "final_classification", "")
        ),
        "risk_score": _safe_int(_value(report, "risk_score", 0)),
        "audit_schema_version": _safe_text(_value(report, "schema_version", "")),
        "policy_version": _safe_text(_value(report, "policy_version", "")),
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
        if len(reports) > _MAX_BASELINE_REPORTS:
            raise ValueError(
                f"baseline contains {len(reports)} reports; "
                f"maximum is {_MAX_BASELINE_REPORTS}"
            )
        if not all(isinstance(item, dict) for item in reports):
            raise ValueError("baseline aggregate contains a non-object report")
        return list(reports)
    if payload.get("repository"):
        return [payload]
    raise ValueError(
        "baseline JSON must be an aggregate audit report or one plugin report"
    )


def load_baseline_report(path: str) -> dict[str, dict[str, Any]]:
    """Load an explicit baseline audit artifact, indexed by repository."""
    size = os.path.getsize(path)
    if size > _MAX_BASELINE_BYTES:
        raise ValueError(
            f"baseline report is {size} bytes; maximum is {_MAX_BASELINE_BYTES}"
        )
    with open(path, encoding="utf-8") as handle:
        payload = json.load(handle)

    indexed: dict[str, dict[str, Any]] = {}
    for report in _reports_from_payload(payload):
        key = _normalise_repository(report.get("repository"))
        if not key:
            raise ValueError("baseline report is missing a repository")
        if key in indexed:
            raise ValueError(
                "baseline contains more than one report for repository "
                f"{report.get('repository')!r}"
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


def _capability_network_destinations(
    capability: dict[str, Any],
) -> set[str]:
    return {
        _safe_text(item.get("destination") or "")
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict)
        and item.get("kind") == "network_destination"
        and item.get("destination")
    }


def _network_destinations(
    report: object,
    capability: dict[str, Any],
) -> set[str]:
    structured = _value(report, "network_destinations", _MISSING)
    if structured is not _MISSING and isinstance(structured, list):
        return {
            _safe_text(_value(item, "destination", ""))
            for item in structured
            if _value(item, "destination", "")
        }

    legacy = _value(report, "extracted_domains", _MISSING)
    if legacy is not _MISSING and isinstance(legacy, list):
        return {_safe_text(value) for value in legacy if value}

    return _capability_network_destinations(capability)


def _native_key(item: object) -> str:
    path = _safe_text(_value(item, "path", ""))
    digest = _safe_text(_value(item, "sha256", ""))
    if path and digest:
        return f"{path} @ sha256:{digest}"
    if digest:
        return f"sha256:{digest}"
    if path:
        return path
    return ""


def _capability_native_binaries(capability: dict[str, Any]) -> set[str]:
    return {
        key
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict) and item.get("kind") == "native_binary"
        if (key := _native_key(item))
    }


def _native_binaries(
    report: object,
    capability: dict[str, Any],
) -> set[str]:
    structured = _value(report, "native_binaries", _MISSING)
    if structured is not _MISSING and isinstance(structured, list):
        return {key for item in structured if (key := _native_key(item))}
    return _capability_native_binaries(capability)


def _capability_source_counts(
    capability: dict[str, Any],
) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in list(capability.get("evidence") or []):
        if (
            isinstance(item, dict)
            and item.get("kind") == "source_artifact_diff"
            and item.get("category")
        ):
            counts[_safe_text(item["category"])] = _safe_int(item.get("count"))
    return counts


def _source_difference_counts(
    report: object,
    capability: dict[str, Any],
) -> dict[str, int]:
    diff = _value(report, "source_artifact_diff", _MISSING)
    if diff is not _MISSING and isinstance(diff, dict):
        counts: dict[str, int] = {}
        for category in _SOURCE_DIFF_CATEGORIES:
            values = diff.get(category)
            if isinstance(values, list) and values:
                counts[category] = len(values)
        return counts
    return _capability_source_counts(capability)


def _rule_ids(capability: dict[str, Any]) -> set[str]:
    return {
        _safe_text(value)
        for value in list(capability.get("rule_ids") or [])
        if value
    }


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
    baseline_report: object,
    current_report: object,
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
        old = _network_destinations(baseline_report, previous)
        new = _network_destinations(current_report, current)
        added, removed = sorted(new - old), sorted(old - new)
        if added or removed:
            kinds.append("network_destinations_changed")
            details["added_destinations"] = added
            details["removed_destinations"] = removed

    if capability_id == "native_code":
        old = _native_binaries(baseline_report, previous)
        new = _native_binaries(current_report, current)
        added, removed = sorted(new - old), sorted(old - new)
        if added or removed:
            kinds.append("native_binaries_changed")
            details["added_native_binaries"] = added
            details["removed_native_binaries"] = removed

    if capability_id == "source_release_integrity":
        old = _source_difference_counts(baseline_report, previous)
        new = _source_difference_counts(current_report, current)
        old_categories, new_categories = set(old), set(new)
        added = sorted(new_categories - old_categories)
        removed = sorted(old_categories - new_categories)
        changed_counts = sorted(
            f"{category}: {old[category]} -> {new[category]}"
            for category in old_categories & new_categories
            if old[category] != new[category]
        )
        if added or removed or changed_counts:
            kinds.append("source_difference_profile_changed")
            details["added_source_difference_categories"] = added
            details["removed_source_difference_categories"] = removed
            details["changed_source_difference_counts"] = changed_counts

    return kinds, details


def _full_current_network_evidence(
    report: object,
    capability: dict[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        return [
            dict(item)
            for item, _confidence in provenance._network_evidence(report)
        ]
    return [
        dict(item)
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict) and item.get("kind") == "network_destination"
    ]


def _full_current_native_evidence(
    report: object,
    capability: dict[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        return [
            dict(item)
            for item, _confidence in provenance._structured("native_code", report)
        ]
    return [
        dict(item)
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict) and item.get("kind") == "native_binary"
    ]


def _full_current_source_evidence(
    report: object,
    capability: dict[str, Any],
) -> list[dict[str, Any]]:
    if not isinstance(report, dict):
        return [
            dict(item)
            for item, _confidence in provenance._source_evidence(report)
        ]
    return [
        dict(item)
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict)
        and item.get("kind") == "source_artifact_diff"
    ]


def _current_change_evidence(
    capability: dict[str, Any],
    current_report: object,
    status_change: str,
    evidence_changes: list[str],
    details: dict[str, list[str]],
) -> list[dict[str, Any]]:
    capability_evidence = [
        dict(item)
        for item in list(capability.get("evidence") or [])
        if isinstance(item, dict)
    ]
    if status_change in {"newly_observed", "now_observed_after_unknown"}:
        return capability_evidence[:_MAX_CHANGE_EVIDENCE]

    selected: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    def add(
        items: list[dict[str, Any]],
        predicate: Callable[[dict[str, Any]], bool],
    ) -> None:
        for item in items:
            if len(selected) >= _MAX_CHANGE_EVIDENCE:
                return
            if not predicate(item):
                continue
            key = (
                str(item.get("kind") or ""),
                json.dumps(item, sort_keys=True, default=str),
            )
            if key in seen:
                continue
            seen.add(key)
            selected.append(item)

    if "network_destinations_changed" in evidence_changes:
        added = set(details.get("added_destinations", []))
        add(
            _full_current_network_evidence(current_report, capability),
            lambda item: (
                item.get("kind") == "network_destination"
                and _safe_text(item.get("destination") or "") in added
            ),
        )

    if "native_binaries_changed" in evidence_changes:
        added = set(details.get("added_native_binaries", []))
        add(
            _full_current_native_evidence(current_report, capability),
            lambda item: (
                item.get("kind") == "native_binary"
                and _native_key(item) in added
            ),
        )

    if "source_difference_profile_changed" in evidence_changes:
        interesting = set(details.get("added_source_difference_categories", []))
        interesting.update(
            value.split(":", 1)[0]
            for value in details.get("changed_source_difference_counts", [])
        )
        add(
            _full_current_source_evidence(current_report, capability),
            lambda item: (
                item.get("kind") == "source_artifact_diff"
                and _safe_text(item.get("category") or "") in interesting
            ),
        )

    if "rule_profile_changed" in evidence_changes:
        added_rules = set(details.get("added_rule_ids", []))
        add(
            capability_evidence,
            lambda item: (
                item.get("kind") == "finding"
                and _safe_text(item.get("rule_id") or "") in added_rules
            ),
        )

    return selected


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
        parts.append(f"{previous_status} -> {current_status}")
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
        changed_counts = len(details.get("changed_source_difference_counts", []))
        suffix = f" ({changed_counts} count change(s))" if changed_counts else ""
        parts.append(f"source/release difference profile changed{suffix}")
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
    """Compare one current report against one explicitly supplied baseline."""
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
            "No baseline report matched this repository. "
            "No release comparison was inferred."
        )
        return comparison

    baseline_schema = str(
        _value(
            baseline_report,
            "reviewer_capabilities_schema_version",
            "",
        )
        or ""
    )
    current_schema = str(
        _value(
            current_report,
            "reviewer_capabilities_schema_version",
            "",
        )
        or ""
    )
    if not baseline_schema or not _capability_map(baseline_report):
        comparison["status"] = "baseline_capabilities_unavailable"
        comparison["status_reason"] = (
            "The baseline report predates reviewer capability summaries "
            "or does not contain them."
        )
        return comparison
    if baseline_schema != _SUPPORTED_CAPABILITY_SCHEMA_VERSION:
        comparison["status"] = "baseline_schema_unsupported"
        comparison["status_reason"] = (
            "Baseline reviewer capability schema "
            f"{baseline_schema!r} is not supported."
        )
        return comparison
    if current_schema != _SUPPORTED_CAPABILITY_SCHEMA_VERSION:
        comparison["status"] = "current_schema_unsupported"
        comparison["status_reason"] = (
            "Current reviewer capability schema "
            f"{current_schema!r} is not supported."
        )
        return comparison

    previous_caps = _capability_map(baseline_report)
    current_caps = _capability_map(current_report)
    if set(previous_caps) != set(current_caps):
        comparison["status"] = "capability_set_mismatch"
        comparison["status_reason"] = (
            "Baseline and current reports do not expose the same "
            "capability identifiers."
        )
        return comparison

    valid_statuses = {"observed", "not_observed", "unknown"}
    for capability_id in current_caps:
        previous_status = _safe_text(
            previous_caps[capability_id].get("status") or ""
        )
        current_status = _safe_text(
            current_caps[capability_id].get("status") or ""
        )
        if (
            previous_status not in valid_statuses
            or current_status not in valid_statuses
        ):
            comparison["status"] = "capability_status_invalid"
            comparison["status_reason"] = (
                f"Capability {capability_id!r} contains an unsupported "
                "status value."
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
            capability_id,
            previous,
            current,
            baseline_report,
            current_report,
        )
        changed = transition != "unchanged" or bool(evidence_change_types)
        item = {
            "id": capability_id,
            "title": _safe_text(
                current.get("title")
                or previous.get("title")
                or capability_id
            ),
            "question": _safe_text(
                current.get("question")
                or previous.get("question")
                or ""
            ),
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
            "baseline_evidence_count": _safe_int(
                previous.get("evidence_count")
            ),
            "current_evidence_count": _safe_int(
                current.get("evidence_count")
            ),
            "details": details,
            "current_change_evidence": _current_change_evidence(
                current,
                current_report,
                transition,
                evidence_change_types,
                details,
            ),
        }
        changes.append(item)

    comparison["status"] = "compared"
    comparison["status_reason"] = (
        "Reviewer capability schemas are compatible."
    )
    comparison["capabilities"] = changes
    comparison["changed_count"] = sum(
        1 for item in changes if item["changed"]
    )
    comparison["attention_count"] = sum(
        1 for item in changes if item["reviewer_attention"]
    )
    return comparison


def _render_identity(identity: dict[str, Any]) -> str:
    release = provenance._code(identity.get("release") or "not recorded")
    artifact = provenance._code(
        identity.get("artifact_sha256") or "not recorded"
    )
    commit = provenance._code(
        identity.get("source_commit") or "not recorded"
    )
    classification = provenance._code(
        identity.get("final_classification") or "not recorded"
    )
    return (
        f"release {release}; artifact {artifact}; source {commit}; "
        f"classification {classification}"
    )


def render_reviewer_capability_comparison(
    comparison: dict[str, Any],
) -> str:
    """Render a reviewer-first Markdown delta without overstating causality."""
    lines = ["## Capability Changes Against Baseline", ""]
    status = str(comparison.get("status") or "unavailable")
    if status != "compared":
        lines.extend(
            [
                "> **Comparison unavailable:** "
                f"{provenance._md(comparison.get('status_reason') or status)}",
                "",
                (
                    "No previous-release behavior was inferred from missing "
                    "or incompatible data."
                ),
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            (
                "> **Interpretation:** This compares two audit reports. "
                "A delta is reviewer evidence, not proof that plugin release "
                "bytes caused the change; scanner coverage, rules, or audit "
                "semantics may also differ."
            ),
            "",
            f"- Baseline: {_render_identity(dict(comparison.get('baseline') or {}))}",
            f"- Current: {_render_identity(dict(comparison.get('current') or {}))}",
            "- Same artifact: "
            f"{provenance._code('yes' if comparison.get('same_artifact') else 'no')}",
            "",
        ]
    )

    changed = [
        item
        for item in list(comparison.get("capabilities") or [])
        if isinstance(item, dict) and item.get("changed")
    ]
    if comparison.get("same_artifact") and changed:
        lines.extend(
            [
                (
                    "> **Same artifact:** the SHA-256 values match, so these "
                    "differences cannot be attributed to different artifact "
                    "bytes."
                ),
                "",
            ]
        )

    if not changed:
        lines.append(
            "No reviewer capability or tracked evidence-profile changes "
            "were detected."
        )
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

    detail_keys = (
        "added_destinations",
        "removed_destinations",
        "added_native_binaries",
        "removed_native_binaries",
        "added_source_difference_categories",
        "removed_source_difference_categories",
        "changed_source_difference_counts",
        "added_rule_ids",
        "removed_rule_ids",
    )
    for item in changed:
        evidence = list(item.get("current_change_evidence") or [])
        details = dict(item.get("details") or {})
        lines.extend(
            [
                "",
                f"### {provenance._md(item.get('title') or item.get('id'))}",
                "",
            ]
        )
        lines.append(
            provenance._md(item.get("summary") or "changed") + "."
        )
        for key in detail_keys:
            values = list(details.get(key) or [])
            if values:
                label = key.replace("_", " ")
                rendered = ", ".join(
                    provenance._code(value) for value in values
                )
                lines.append(
                    f"- {provenance._md(label.capitalize())}: {rendered}"
                )
        if evidence:
            lines.append("- Current evidence:")
            for evidence_item in evidence:
                lines.append(
                    f"  - {provenance._render_evidence(evidence_item)}"
                )
    return "\n".join(lines).rstrip()


def _insert_comparison(markdown: str, section: str) -> str:
    marker = "## Reviewer Capability Summary"
    if marker not in markdown:
        return f"{section}\n\n{markdown}"
    return markdown.replace(marker, f"{section}\n\n{marker}", 1)


def _extract_baseline_option(
    argv: Sequence[str],
) -> tuple[list[str], str | None]:
    stripped: list[str] = []
    baseline_path: str | None = None
    index = 0
    while index < len(argv):
        arg = argv[index]
        if arg == "--baseline-report":
            if baseline_path is not None:
                raise ValueError(
                    "--baseline-report may only be supplied once"
                )
            if index + 1 >= len(argv):
                raise ValueError("--baseline-report requires a path")
            baseline_path = argv[index + 1]
            index += 2
            continue
        if arg.startswith("--baseline-report="):
            if baseline_path is not None:
                raise ValueError(
                    "--baseline-report may only be supplied once"
                )
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
    if not getattr(
        core,
        "_reviewer_evidence_provenance_installed",
        False,
    ):
        raise RuntimeError(
            "reviewer_evidence_provenance must be installed first"
        )

    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_report_to_dict: Callable[[Any], dict[str, Any]] = (
        core._report_to_dict
    )
    raw_generate_markdown: Callable[[Any], str] = (
        core.generate_markdown_report
    )
    raw_main: Callable[[Sequence[str] | None], int] = core.main

    def audit_repository(*args: Any, **kwargs: Any) -> Any:
        report = raw_audit_repository(*args, **kwargs)
        baselines = _ACTIVE_BASELINES
        if baselines is not None:
            key = _normalise_repository(
                _value(report, "repository", "")
            )
            baseline = baselines.get(key)
            report.reviewer_capability_comparison_schema_version = (
                REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION
            )
            report.reviewer_capability_comparison = (
                compare_reviewer_capabilities(report, baseline)
            )
        return report

    def report_to_dict(report: Any) -> dict[str, Any]:
        payload = raw_report_to_dict(report)
        comparison = getattr(
            report,
            "reviewer_capability_comparison",
            None,
        )
        if comparison is not None:
            payload[
                "reviewer_capability_comparison_schema_version"
            ] = REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION
            payload["reviewer_capability_comparison"] = comparison
        return payload

    def generate_markdown_report(report: Any) -> str:
        rendered = raw_generate_markdown(report)
        comparison = getattr(
            report,
            "reviewer_capability_comparison",
            None,
        )
        if comparison is None:
            return rendered
        return _insert_comparison(
            rendered,
            render_reviewer_capability_comparison(comparison),
        )

    def main(argv: Sequence[str] | None = None) -> int:
        import sys

        resolved = (
            list(argv)
            if argv is not None
            else list(sys.argv[1:])
        )
        try:
            stripped, baseline_path = _extract_baseline_option(
                resolved
            )
            baselines = (
                load_baseline_report(
                    os.path.abspath(baseline_path)
                )
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
    core.render_reviewer_capability_comparison = (
        render_reviewer_capability_comparison
    )
    core.load_baseline_report = load_baseline_report
    core.REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION = (
        REVIEWER_CAPABILITY_COMPARISON_SCHEMA_VERSION
    )
    core._reviewer_capability_comparison_installed = True
    return core
