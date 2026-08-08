"""Derive reviewer-oriented capability groups from existing audit evidence.

This module is intentionally additive. It does not create findings, change risk
scores, alter classifications, or influence enforcement. Instead, it groups the
auditor's existing findings and structured evidence into stable questions that a
human reviewer can scan before drilling into the raw report.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field, make_dataclass
from types import ModuleType
from typing import Any, Callable


REVIEWER_CAPABILITY_SCHEMA_VERSION = "1"


@dataclass(frozen=True)
class _CapabilitySpec:
    capability_id: str
    title: str
    question: str


_CAPABILITIES = (
    _CapabilitySpec(
        "command_execution",
        "Command and process execution",
        "Can the plugin execute commands or start other programs?",
    ),
    _CapabilitySpec(
        "privileged_system_access",
        "Privileged and system-level access",
        "Can the plugin request elevated privileges or control system-level resources?",
    ),
    _CapabilitySpec(
        "persistence",
        "Persistence and automatic startup",
        "Can the plugin establish persistence or start automatically?",
    ),
    _CapabilitySpec(
        "network_communication",
        "Network communication",
        "What network communication capability or destination evidence is present?",
    ),
    _CapabilitySpec(
        "sensitive_data_access",
        "Credentials and sensitive data",
        "Can the plugin access credentials, secrets, keys, or other sensitive data?",
    ),
    _CapabilitySpec(
        "native_code",
        "Native executable code",
        "Does the plugin include native executable code that needs separate review?",
    ),
    _CapabilitySpec(
        "source_release_integrity",
        "Published release versus source",
        "Does the published release materially differ from the exact source used for review?",
    ),
    _CapabilitySpec(
        "malware",
        "Malware detection",
        "Did malware scanning identify malicious content in the published release?",
    ),
    _CapabilitySpec(
        "known_vulnerabilities",
        "Known vulnerabilities",
        "Did dependency or vulnerability scanners identify known vulnerable components?",
    ),
)

_CONFIDENCE_RANK = {"none": 0, "unknown": 0, "low": 1, "medium": 2, "high": 3}
_CLASSIFICATION_RANK = {
    "BLOCK": 0,
    "MANUAL_REVIEW": 1,
    "PASS_WITH_WARNINGS": 2,
    "PASS": 3,
}
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
_MAX_EVIDENCE_PER_CAPABILITY = 20
_INCOMPLETE_SCANNER_STATES = {"failed", "unavailable", "unsupported"}


def _value(item: object, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _rule_key(finding: object) -> str:
    value = str(_value(finding, "rule_id", "") or "").upper()
    return re.sub(r"[^A-Z0-9]+", "_", value).strip("_")


def _scanner_key(finding: object) -> str:
    return str(_value(finding, "scanner", "") or "").casefold().replace("_", "-")


def _finding_sort_key(finding: object) -> tuple[Any, ...]:
    return (
        _CLASSIFICATION_RANK.get(str(_value(finding, "classification", "") or ""), 99),
        _SEVERITY_RANK.get(str(_value(finding, "severity", "") or "").casefold(), 99),
        str(_value(finding, "rule_id", "") or ""),
        str(_value(finding, "path", "") or ""),
        int(_value(finding, "line", 0) or 0),
    )


def _finding_confidence(finding: object) -> str:
    severity = str(_value(finding, "severity", "") or "").casefold()
    if severity in {"critical", "high"}:
        return "high"
    if severity == "medium":
        return "medium"
    return "low"


def _matches_finding(capability_id: str, finding: object) -> bool:
    rule = _rule_key(finding)
    scanner = _scanner_key(finding)
    tokens = set(rule.split("_")) if rule else set()

    if capability_id == "command_execution":
        return (
            rule.startswith("EXEC_")
            or "DYNAMIC_EXECUTION" in rule
            or "SHELL_COMMAND" in rule
            or "CHILD_PROCESS" in rule
            or "CURL_PIPE" in rule
            or "SUBPROCESS" in tokens
            or "EXEC" in tokens
        )

    if capability_id == "privileged_system_access":
        return (
            rule == "ROOT_ACCESS"
            or rule.startswith("PRIVILEGE_")
            or bool(tokens & {"SUDO", "PKEXEC", "UDEV", "MOUNT", "KERNEL"})
            or "SYSTEM_CONTROL" in rule
            or "SYSTEM_MODIFICATION" in rule
        )

    if capability_id == "persistence":
        return (
            rule.startswith("PERSIST_")
            or "SYSTEMD_SERVICE" in rule
            or "SCHEDULED_TASK" in rule
            or bool(tokens & {"AUTOSTART", "STARTUP", "CRON", "PERSISTENCE"})
        )

    if capability_id == "network_communication":
        return (
            rule.startswith("NETWORK_")
            or "HTTP_REQUEST" in rule
            or "WEBSOCKET" in rule
            or bool(tokens & {"SOCKET", "DOWNLOAD", "UPLOAD", "EXFILTRATION"})
        )

    if capability_id == "sensitive_data_access":
        return (
            rule.startswith("CREDENTIAL_")
            or rule.startswith("SENSITIVE_")
            or "PRIVATE_KEY" in rule
            or bool(tokens & {"SECRET", "SECRETS", "KEYRING", "CREDENTIAL", "CREDENTIALS"})
            or ("PASS" + "WORD") in tokens
        )

    if capability_id == "native_code":
        return (
            "NATIVE_BINARY" in rule
            or rule.startswith("BINARY_")
            or rule.endswith("_EXECUTABLE")
            or rule.endswith("_EXECUTABLES")
            or rule == "LARGE_BINARY_ABSENT_FROM_SOURCE"
        )

    if capability_id == "source_release_integrity":
        return (
            rule.startswith("ZIP_ONLY_")
            or rule in {
                "SAME_PATH_CONTENT_MISMATCH",
                "GENERATED_SAME_PATH_CONTENT_DIFF",
                "LARGE_BINARY_ABSENT_FROM_SOURCE",
                "UNEXPECTED_RELEASE_URL",
            }
            or "SOURCE_ARTIFACT" in rule
            or "ARTIFACT_SOURCE" in rule
        )

    if capability_id == "malware":
        return rule == "MALWARE" or scanner == "clamav"

    if capability_id == "known_vulnerabilities":
        return (
            scanner in {"trivy", "osv", "osv-scanner"}
            or "VULNERAB" in rule
            or "CVE" in tokens
            or rule.startswith("OSV_")
        )

    return False


def _finding_evidence(finding: object) -> dict[str, Any]:
    return {
        "kind": "finding",
        "rule_id": str(_value(finding, "rule_id", "") or ""),
        "path": str(_value(finding, "path", "") or ""),
        "line": int(_value(finding, "line", 0) or 0),
        "severity": str(_value(finding, "severity", "") or ""),
        "classification": str(_value(finding, "classification", "") or ""),
        "scanner": str(_value(finding, "scanner", "") or ""),
        "allowlisted": bool(_value(finding, "allowlisted", False)),
    }


def _normalise_source(source: object) -> dict[str, Any]:
    record = {
        "path": str(_value(source, "path", "") or ""),
        "line": int(_value(source, "line", 0) or 0),
        "provenance": str(_value(source, "provenance", "") or ""),
        "confidence": str(_value(source, "confidence", "unknown") or "unknown"),
    }
    for key in ("source_status", "source_url", "source_path", "source_commit"):
        value = _value(source, key, None)
        if value:
            record[key] = str(value)
    return record


def _network_evidence(report: object) -> list[tuple[dict[str, Any], str]]:
    destinations = list(getattr(report, "network_destinations", []) or [])
    evidence: list[tuple[dict[str, Any], str]] = []
    if destinations:
        destinations.sort(
            key=lambda item: (
                -_CONFIDENCE_RANK.get(str(_value(item, "confidence", "unknown") or "unknown"), 0),
                str(_value(item, "destination", "") or "").casefold(),
            )
        )
        for item in destinations:
            confidence = str(_value(item, "confidence", "low") or "low")
            sources = [_normalise_source(source) for source in list(_value(item, "sources", []) or [])]
            sources.sort(
                key=lambda source: (
                    source.get("path", ""),
                    int(source.get("line", 0) or 0),
                    source.get("provenance", ""),
                    source.get("source_url", ""),
                )
            )
            evidence.append(({
                "kind": "network_destination",
                "destination": str(_value(item, "destination", "") or ""),
                "confidence": confidence,
                "review_priority": str(_value(item, "review_priority", "") or ""),
                "reason": str(_value(item, "reason", "") or ""),
                "sources": sources[:3],
            }, confidence if confidence in _CONFIDENCE_RANK else "low"))
        return evidence

    # Older cached reports may only have the legacy flat destination list.
    for destination in sorted(str(item) for item in list(getattr(report, "extracted_domains", []) or [])):
        evidence.append(({
            "kind": "network_destination",
            "destination": destination,
            "confidence": "low",
            "review_priority": "inventory",
            "reason": "legacy destination inventory without per-file provenance",
            "sources": [],
        }, "low"))
    return evidence


def _native_evidence(report: object) -> list[tuple[dict[str, Any], str]]:
    binaries = list(getattr(report, "native_binaries", []) or [])
    binaries.sort(
        key=lambda item: (
            str(_value(item, "path", "") or ""),
            str(_value(item, "sha256", "") or ""),
        )
    )
    evidence: list[tuple[dict[str, Any], str]] = []
    for binary in binaries:
        evidence.append(({
            "kind": "native_binary",
            "path": str(_value(binary, "path", "") or ""),
            "label": str(_value(binary, "label", "") or ""),
            "architecture": str(_value(binary, "architecture", "") or ""),
            "sha256": str(_value(binary, "sha256", "") or ""),
        }, "high"))
    return evidence


def _source_integrity_evidence(report: object) -> list[tuple[dict[str, Any], str]]:
    diff = dict(getattr(report, "source_artifact_diff", {}) or {})
    if not diff.get("checked"):
        return []

    categories = (
        ("zip_only_executables", "high"),
        ("zip_only_scripts", "high"),
        ("large_binaries_absent_from_source", "high"),
        ("unexpected_urls", "high"),
        ("same_path_modified", "high"),
        ("grouped_packaged_outputs", "low"),
        ("generated_or_dependency_differences", "low"),
        ("other_same_path_differences", "low"),
        ("expected_build_stamp_differences", "low"),
    )
    evidence: list[tuple[dict[str, Any], str]] = []
    for category, confidence in categories:
        values = list(diff.get(category) or [])
        if not values:
            continue
        samples: list[str] = []
        for value in values:
            if isinstance(value, dict):
                sample = value.get("artifact_path") or value.get("path") or value.get("source_path")
            else:
                sample = value
            if not sample:
                continue
            sample_text = str(sample)
            if sample_text in samples:
                continue
            if len(samples) < 5:
                samples.append(sample_text)
                samples.sort()
            elif sample_text < samples[-1]:
                samples.append(sample_text)
                samples.sort()
                samples.pop()
        evidence.append(({
            "kind": "source_artifact_diff",
            "category": category,
            "count": len(values),
            "sample_paths": samples,
        }, confidence))
    return evidence


def _structured_evidence(capability_id: str, report: object) -> list[tuple[dict[str, Any], str]]:
    if capability_id == "network_communication":
        return _network_evidence(report)
    if capability_id == "native_code":
        return _native_evidence(report)
    if capability_id == "source_release_integrity":
        return _source_integrity_evidence(report)
    return []


def _scanner_status(report: object, *names: str) -> str:
    wanted = {name.casefold().replace("_", "-") for name in names}
    for item in list(getattr(report, "scanner_statuses", []) or []):
        name = str(_value(item, "name", "") or "").casefold().replace("_", "-")
        if name in wanted:
            return str(_value(item, "status", "") or "").casefold()
    return ""


def _vulnerability_scanner_states(report: object) -> dict[str, str]:
    states: dict[str, str] = {}
    for name in ("trivy", "osv", "osv-scanner"):
        state = _scanner_status(report, name)
        if state:
            states[name] = state
    return states


def _status_without_evidence(capability_id: str, report: object) -> tuple[str, str]:
    if capability_id == "source_release_integrity":
        diff = dict(getattr(report, "source_artifact_diff", {}) or {})
        if diff.get("checked"):
            return "not_observed", "Exact release-to-source comparison completed without matching evidence."
        state = _scanner_status(report, "source-artifact-diff")
        detail = f" (scanner status: {state})" if state else ""
        return "unknown", f"Exact release-to-source comparison did not complete{detail}."

    if capability_id == "malware":
        state = _scanner_status(report, "clamav")
        if state == "passed":
            return "not_observed", "ClamAV completed without a malware finding."
        if state == "found_issue":
            return "unknown", "ClamAV reported an issue but no malware finding was available to this capability summary."
        if state:
            return "unknown", f"Malware coverage is incomplete because ClamAV status is {state}."
        return "unknown", "Malware coverage is unknown because no ClamAV scanner status was recorded."

    if capability_id == "known_vulnerabilities":
        states = _vulnerability_scanner_states(report)
        attempted = {name: state for name, state in states.items() if state != "skipped"}
        incomplete = {name: state for name, state in attempted.items() if state in _INCOMPLETE_SCANNER_STATES}
        if incomplete:
            details = ", ".join(f"{name}={state}" for name, state in sorted(incomplete.items()))
            return "unknown", f"Vulnerability scanner coverage is incomplete: {details}."
        if any(state == "found_issue" for state in attempted.values()):
            return "unknown", "A vulnerability scanner reported an issue but no matching finding was available to this capability summary."
        if any(state == "passed" for state in attempted.values()):
            return "not_observed", "Available vulnerability scanner coverage completed without matching findings."
        if states:
            details = ", ".join(f"{name}={state}" for name, state in sorted(states.items()))
            return "unknown", f"No vulnerability scanner completed successfully: {details}."
        return "unknown", "Vulnerability coverage is unknown because no vulnerability scanner status was recorded."

    if str(getattr(report, "final_classification", "") or "") == "AUDIT_ERROR":
        return "unknown", "The audit ended with AUDIT_ERROR, so absence of evidence is not a reliable clean result."

    return "not_observed", "The completed static audit found no supporting evidence for this capability."


def _max_confidence(values: list[str]) -> str:
    if not values:
        return "none"
    return max(values, key=lambda value: _CONFIDENCE_RANK.get(value, 0))


def summarize_reviewer_capabilities(report: object) -> list[dict[str, Any]]:
    """Return deterministic capability groups derived from existing evidence.

    Allowlisted findings remain visible here because an exception changes an
    enforcement decision, not whether the underlying capability evidence exists.
    """
    findings = list(getattr(report, "findings", []) or [])
    capabilities: list[dict[str, Any]] = []

    for spec in _CAPABILITIES:
        matched = sorted(
            [finding for finding in findings if _matches_finding(spec.capability_id, finding)],
            key=_finding_sort_key,
        )
        compact_evidence: list[dict[str, Any]] = []
        confidences: list[str] = []

        for finding in matched:
            if len(compact_evidence) < _MAX_EVIDENCE_PER_CAPABILITY:
                compact_evidence.append(_finding_evidence(finding))
            confidences.append(_finding_confidence(finding))

        structured = _structured_evidence(spec.capability_id, report)
        for item, confidence in structured:
            if len(compact_evidence) < _MAX_EVIDENCE_PER_CAPABILITY:
                compact_evidence.append(item)
            confidences.append(confidence)

        total = len(matched) + len(structured)
        rule_ids = sorted({
            str(_value(finding, "rule_id", "") or "")
            for finding in matched
            if _value(finding, "rule_id", "")
        })
        substantive_evidence = total > 0
        if spec.capability_id == "source_release_integrity":
            substantive_evidence = bool(structured) or any(
                _rule_key(finding) != "SOURCE_ARTIFACT_DIFF_INCOMPLETE"
                for finding in matched
            )
        if substantive_evidence:
            status = "observed"
            status_reason = "Supporting audit evidence was found."
        else:
            status, status_reason = _status_without_evidence(spec.capability_id, report)

        capabilities.append({
            "id": spec.capability_id,
            "title": spec.title,
            "question": spec.question,
            "status": status,
            "status_reason": status_reason,
            "confidence": _max_confidence(confidences),
            "finding_count": len(matched),
            "evidence_count": total,
            "rule_ids": rule_ids,
            "evidence": compact_evidence,
            "evidence_truncated": total > _MAX_EVIDENCE_PER_CAPABILITY,
        })

    return capabilities


def _ensure_capabilities(report: object) -> list[dict[str, Any]]:
    capabilities = summarize_reviewer_capabilities(report)
    setattr(report, "reviewer_capabilities_schema_version", REVIEWER_CAPABILITY_SCHEMA_VERSION)
    setattr(report, "reviewer_capabilities", capabilities)
    return capabilities


def _render_evidence(item: dict[str, Any]) -> str:
    kind = item.get("kind")
    if kind == "finding":
        location = str(item.get("path") or "")
        line = int(item.get("line") or 0)
        if location:
            location = f"`{location}:{line}`" if line else f"`{location}`"
        else:
            location = "report-level evidence"
        allowlisted = " — allowlisted exception" if item.get("allowlisted") else ""
        return f"`{item.get('rule_id')}` at {location}{allowlisted}"

    if kind == "network_destination":
        reason = str(item.get("reason") or "network reference")
        return (
            f"network destination `{item.get('destination')}` — "
            f"{item.get('confidence', 'low')} confidence; {reason}"
        )

    if kind == "native_binary":
        details = str(item.get("label") or "native binary")
        architecture = str(item.get("architecture") or "")
        if architecture:
            details += f", {architecture}"
        return f"native binary `{item.get('path')}` — {details}"

    if kind == "source_artifact_diff":
        samples = list(item.get("sample_paths") or [])
        sample_text = ", ".join(f"`{path}`" for path in samples[:3])
        suffix = f"; examples: {sample_text}" if sample_text else ""
        return (
            f"source/artifact `{item.get('category')}` — "
            f"{item.get('count', 0)} item(s){suffix}"
        )

    return str(item)


def render_reviewer_capabilities(capabilities: list[dict[str, Any]]) -> str:
    lines = [
        "## Reviewer Capability Summary",
        "",
        (
            "> **Interpretation:** `not_observed` means relevant audit coverage completed without "
            "supporting evidence. `unknown` means coverage was incomplete or unavailable. Neither "
            "status proves that a capability is impossible."
        ),
        "",
        "| Reviewer question | Status | Confidence | Evidence |",
        "|---|---|---|---:|",
    ]

    status_icons = {"observed": "🔎", "not_observed": "➖", "unknown": "❓"}
    for capability in capabilities:
        status = str(capability.get("status") or "unknown")
        confidence = str(capability.get("confidence") or "none")
        lines.append(
            f"| {capability.get('question')} | {status_icons.get(status, '❓')} `{status}` | "
            f"`{confidence}` | {capability.get('evidence_count', 0)} |"
        )

    attention = [cap for cap in capabilities if cap.get("status") in {"observed", "unknown"}]
    for capability in attention:
        lines.extend([
            "",
            f"### {capability.get('title')}",
            "",
            f"**Question:** {capability.get('question')}",
            "",
        ])
        if capability.get("status") == "unknown":
            lines.extend([
                f"**Coverage:** {capability.get('status_reason', 'Coverage is incomplete.')}",
                "",
            ])
        evidence = list(capability.get("evidence") or [])
        for item in evidence:
            lines.append(f"- {_render_evidence(item)}")
        if capability.get("evidence_truncated"):
            hidden = int(capability.get("evidence_count") or 0) - len(evidence)
            lines.append(
                f"- _{hidden} additional evidence item(s) remain available in the raw findings/structured report data._"
            )

    return "\n".join(lines).rstrip()


def _insert_capability_section(markdown: str, section: str) -> str:
    marker = "\n## Findings\n"
    if marker not in markdown:
        return markdown
    return markdown.replace(marker, f"\n{section}\n\n## Findings\n", 1)


def install(core: ModuleType) -> ModuleType:
    """Install additive reviewer capability grouping on the active audit core."""
    if getattr(core, "_reviewer_capabilities_installed", False):
        return core

    base_report = core.AuditReport
    fields_to_add = []
    existing_fields = getattr(base_report, "__dataclass_fields__", {})
    if "reviewer_capabilities_schema_version" not in existing_fields:
        fields_to_add.append((
            "reviewer_capabilities_schema_version",
            str,
            field(default=REVIEWER_CAPABILITY_SCHEMA_VERSION),
        ))
    if "reviewer_capabilities" not in existing_fields:
        fields_to_add.append((
            "reviewer_capabilities",
            list[dict[str, Any]],
            field(default_factory=list),
        ))
    if fields_to_add:
        capability_report = make_dataclass(
            "AuditReport",
            fields_to_add,
            bases=(base_report,),
        )
        capability_report.__module__ = base_report.__module__
        core.AuditReport = capability_report

    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_report_to_dict: Callable[[Any], dict[str, Any]] = core._report_to_dict
    raw_generate_markdown: Callable[[Any], str] = core.generate_markdown_report

    def audit_repository(*args: Any, **kwargs: Any) -> Any:
        report = raw_audit_repository(*args, **kwargs)
        _ensure_capabilities(report)
        return report

    def report_to_dict(report: Any) -> dict[str, Any]:
        _ensure_capabilities(report)
        return raw_report_to_dict(report)

    def generate_markdown_report(report: Any) -> str:
        capabilities = _ensure_capabilities(report)
        rendered = raw_generate_markdown(report)
        return _insert_capability_section(
            rendered,
            render_reviewer_capabilities(capabilities),
        )

    core.audit_repository = audit_repository
    core._report_to_dict = report_to_dict
    core.generate_markdown_report = generate_markdown_report
    core.summarize_reviewer_capabilities = summarize_reviewer_capabilities
    core.render_reviewer_capabilities = render_reviewer_capabilities
    core.REVIEWER_CAPABILITY_SCHEMA_VERSION = REVIEWER_CAPABILITY_SCHEMA_VERSION
    core._reviewer_capabilities_installed = True
    return core
