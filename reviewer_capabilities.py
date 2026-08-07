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
        "known_vulnerabilities",
        "Known vulnerabilities",
        "Did dependency or vulnerability scanners identify known vulnerable components?",
    ),
)

_CONFIDENCE_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3}
_MAX_EVIDENCE_PER_CAPABILITY = 20


def _value(item: object, name: str, default: Any = None) -> Any:
    if isinstance(item, dict):
        return item.get(name, default)
    return getattr(item, name, default)


def _rule_key(finding: object) -> str:
    value = str(_value(finding, "rule_id", "") or "").upper()
    return re.sub(r"[^A-Z0-9]+", "_", value).strip("_")


def _scanner_key(finding: object) -> str:
    return str(_value(finding, "scanner", "") or "").casefold().replace("_", "-")


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
            or "PRIVATE_KEY" in rule
            or "SENSITIVE_SSH_KEY" in rule
            or bool(tokens & {"SECRET", "SECRETS", "KEYRING", "CREDENTIAL", "CREDENTIALS"})
            or ("PASS" + "WORD") in tokens
        )

    if capability_id == "native_code":
        return (
            "NATIVE_BINARY" in rule
            or rule.startswith("BINARY_")
            or rule in {"ZIP_ONLY_EXECUTABLE", "LARGE_BINARY_ABSENT_FROM_SOURCE"}
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


def _network_evidence(report: object) -> list[tuple[dict[str, Any], str]]:
    destinations = list(getattr(report, "network_destinations", []) or [])
    evidence: list[tuple[dict[str, Any], str]] = []
    if destinations:
        for item in destinations:
            confidence = str(_value(item, "confidence", "low") or "low")
            evidence.append(({
                "kind": "network_destination",
                "destination": str(_value(item, "destination", "") or ""),
                "confidence": confidence,
                "review_priority": str(_value(item, "review_priority", "") or ""),
                "reason": str(_value(item, "reason", "") or ""),
            }, confidence if confidence in _CONFIDENCE_RANK else "low"))
        return evidence

    # Older cached reports may only have the legacy flat destination list.
    for destination in list(getattr(report, "extracted_domains", []) or []):
        evidence.append(({
            "kind": "network_destination",
            "destination": str(destination),
            "confidence": "low",
            "review_priority": "inventory",
            "reason": "legacy destination inventory without per-file provenance",
        }, "low"))
    return evidence


def _native_evidence(report: object) -> list[tuple[dict[str, Any], str]]:
    evidence: list[tuple[dict[str, Any], str]] = []
    for binary in list(getattr(report, "native_binaries", []) or []):
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
        ("generated_or_dependency_differences", "low"),
    )
    evidence: list[tuple[dict[str, Any], str]] = []
    for category, confidence in categories:
        values = list(diff.get(category) or [])
        if not values:
            continue
        samples: list[str] = []
        for value in values[:5]:
            if isinstance(value, dict):
                sample = value.get("artifact_path") or value.get("path") or value.get("source_path")
                if sample:
                    samples.append(str(sample))
            else:
                samples.append(str(value))
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
        matched = [finding for finding in findings if _matches_finding(spec.capability_id, finding)]
        compact_evidence: list[dict[str, Any]] = []
        confidences: list[str] = []

        for finding in matched:
            compact_evidence.append(_finding_evidence(finding))
            confidences.append(_finding_confidence(finding))

        structured = _structured_evidence(spec.capability_id, report)
        for item, confidence in structured:
            compact_evidence.append(item)
            confidences.append(confidence)

        total = len(compact_evidence)
        rule_ids = sorted({
            str(_value(finding, "rule_id", "") or "")
            for finding in matched
            if _value(finding, "rule_id", "")
        })
        observed = total > 0
        capabilities.append({
            "id": spec.capability_id,
            "title": spec.title,
            "question": spec.question,
            "status": "observed" if observed else "not_observed",
            "confidence": _max_confidence(confidences),
            "finding_count": len(matched),
            "evidence_count": total,
            "rule_ids": rule_ids,
            "evidence": compact_evidence[:_MAX_EVIDENCE_PER_CAPABILITY],
            "evidence_truncated": total > _MAX_EVIDENCE_PER_CAPABILITY,
        })

    return capabilities


def _ensure_capabilities(report: object) -> list[dict[str, Any]]:
    capabilities = summarize_reviewer_capabilities(report)
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
        "> **Interpretation:** `not_observed` means this static audit found no supporting evidence. It is not proof that the capability is absent.",
        "",
        "| Reviewer question | Status | Confidence | Evidence |",
        "|---|---|---|---:|",
    ]

    status_icons = {"observed": "🔎", "not_observed": "➖"}
    for capability in capabilities:
        status = str(capability.get("status") or "not_observed")
        confidence = str(capability.get("confidence") or "none")
        lines.append(
            f"| {capability.get('question')} | {status_icons.get(status, '❓')} `{status}` | "
            f"`{confidence}` | {capability.get('evidence_count', 0)} |"
        )

    observed = [cap for cap in capabilities if cap.get("status") == "observed"]
    for capability in observed:
        lines.extend([
            "",
            f"### {capability.get('title')}",
            "",
            f"**Question:** {capability.get('question')}",
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
    if "reviewer_capabilities" not in getattr(base_report, "__dataclass_fields__", {}):
        capability_report = make_dataclass(
            "AuditReport",
            [
                (
                    "reviewer_capabilities",
                    list[dict[str, Any]],
                    field(default_factory=list),
                ),
            ],
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
    core._reviewer_capabilities_installed = True
    return core