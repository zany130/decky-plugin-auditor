"""Derive reviewer-oriented capability questions from existing audit evidence.

This module is deliberately additive. It does not change finding generation,
allowlisting, classification, risk scoring, or scanner policy. Instead, it
summarizes evidence the auditor already collected into a stable set of reviewer
questions that can later be compared across accepted plugin releases.
"""

from __future__ import annotations

from dataclasses import dataclass, field, make_dataclass
from types import ModuleType
from typing import Any, Callable, Iterable

_CAPABILITY_SCHEMA_VERSION = "1"
_MAX_EVIDENCE = 8

_STATUS_LABELS = {
    "detected": "DETECTED",
    "review": "REVIEW",
    "not_detected": "NO EVIDENCE",
    "unknown": "UNKNOWN",
}
_STATUS_ICONS = {
    "detected": "🟠",
    "review": "🔍",
    "not_detected": "✅",
    "unknown": "❓",
}
_CLASSIFICATION_RANK = {
    "BLOCK": 0,
    "MANUAL_REVIEW": 1,
    "PASS_WITH_WARNINGS": 2,
    "PASS": 3,
}
_SEVERITY_RANK = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_CONFIDENCE_RANK = {"unknown": 0, "low": 1, "medium": 2, "high": 3}


@dataclass(frozen=True)
class _CapabilityDefinition:
    capability_id: str
    question: str
    exact_rules: tuple[str, ...] = ()
    rule_prefixes: tuple[str, ...] = ()
    rule_contains: tuple[str, ...] = ()


_CAPABILITIES = (
    _CapabilityDefinition(
        "command_execution",
        "Can this plugin execute commands or launch processes?",
        exact_rules=("SHELL_CURL_PIPE", "SHELL_BASE64_EXEC"),
        rule_prefixes=("EXEC_",),
        rule_contains=("_SHELL_COMMAND", "_CHILD_PROCESS_EXEC"),
    ),
    _CapabilityDefinition(
        "dynamic_or_obfuscated_code",
        "Can this plugin dynamically evaluate, load, or conceal code?",
        exact_rules=(
            "EXEC_EVAL",
            "EXEC_EXEC",
            "EXEC_EVAL_JS",
            "EXEC_FUNCTION_CTOR",
            "SHELL_BASE64_EXEC",
        ),
        rule_prefixes=("OBFUSCATION_",),
        rule_contains=("_DYNAMIC_EXECUTION",),
    ),
    _CapabilityDefinition(
        "elevated_privileges",
        "Does this plugin request or use elevated privileges?",
        exact_rules=("ROOT_ACCESS",),
        rule_prefixes=("PRIVILEGE_",),
    ),
    _CapabilityDefinition(
        "host_system_modification",
        "Can this plugin change persistent or host system state?",
        exact_rules=(
            "PRIVILEGE_CHMOD_777",
            "PRIVILEGE_CHMOD_SUID",
            "PRIVILEGE_CHOWN_ROOT",
            "PRIVILEGE_SYSTEMCTL",
            "PRIVILEGE_SYSTEMCTL_SHELL",
            "PRIVILEGE_MOUNT",
            "PRIVILEGE_MODPROBE",
            "PRIVILEGE_IPTABLES",
            "PRIVILEGE_STEAMOS_READONLY",
        ),
        rule_prefixes=("PERSIST_", "DESTRUCTIVE_"),
    ),
    _CapabilityDefinition(
        "network_communication",
        "Does plugin runtime reference network destinations?",
        rule_prefixes=("NETWORK_",),
    ),
    _CapabilityDefinition(
        "sensitive_data_access",
        "Does this plugin access sensitive user or system data?",
        rule_prefixes=("SENSITIVE_",),
    ),
    _CapabilityDefinition(
        "embedded_credentials",
        "Does shipped content contain credential-like material?",
        rule_prefixes=("SECRET_",),
        rule_contains=("_GENERIC_PRIVATE_KEY",),
    ),
    _CapabilityDefinition(
        "native_or_opaque_code",
        "Does the release include native or opaque executable code?",
        exact_rules=(
            "NATIVE_BINARY",
            "ZIP_ONLY_EXECUTABLE",
            "BUNDLED_DEPENDENCY_EXECUTABLES",
            "GENERATED_BUILD_EXECUTABLES",
        ),
    ),
    _CapabilityDefinition(
        "release_source_integrity",
        "Are there release-to-source differences requiring review?",
        exact_rules=(
            "ZIP_ONLY_SCRIPT",
            "ZIP_ONLY_EXECUTABLE",
            "SAME_PATH_CONTENT_MISMATCH",
            "GENERATED_SAME_PATH_CONTENT_DIFF",
            "BUNDLED_DEPENDENCY_SCRIPTS",
            "BUNDLED_DEPENDENCY_EXECUTABLES",
            "VENDORED_DEPENDENCY_SCRIPTS",
            "GENERATED_BUILD_SCRIPTS",
            "GENERATED_BUILD_EXECUTABLES",
            "SOURCE_ARTIFACT_DIFF_INCOMPLETE",
        ),
    ),
    _CapabilityDefinition(
        "malware_or_known_vulnerabilities",
        "Do scanners report malware or known vulnerabilities?",
        exact_rules=("MALWARE",),
        rule_prefixes=("TRIVY_",),
    ),
)


def _rule_matches(definition: _CapabilityDefinition, rule_id: str) -> bool:
    if rule_id in definition.exact_rules:
        return True
    if any(rule_id.startswith(prefix) for prefix in definition.rule_prefixes):
        return True
    return any(fragment in rule_id for fragment in definition.rule_contains)


def _finding_sort_key(finding: Any) -> tuple[Any, ...]:
    return (
        _CLASSIFICATION_RANK.get(str(getattr(finding, "classification", "")), 99),
        _SEVERITY_RANK.get(str(getattr(finding, "severity", "")), 99),
        str(getattr(finding, "rule_id", "")),
        str(getattr(finding, "path", "")),
        int(getattr(finding, "line", 0) or 0),
    )


def _matching_findings(report: Any, definition: _CapabilityDefinition) -> list[Any]:
    return sorted(
        [
            finding
            for finding in (getattr(report, "findings", []) or [])
            if _rule_matches(definition, str(getattr(finding, "rule_id", "") or ""))
        ],
        key=_finding_sort_key,
    )


def _finding_confidence(finding: Any) -> str:
    classification = str(getattr(finding, "classification", "") or "")
    severity = str(getattr(finding, "severity", "") or "")
    if classification in {"BLOCK", "MANUAL_REVIEW"} and severity in {"critical", "high"}:
        return "high"
    if classification in {"BLOCK", "MANUAL_REVIEW"} or severity == "medium":
        return "medium"
    return "low"


def _finding_evidence(finding: Any) -> dict[str, Any]:
    evidence: dict[str, Any] = {
        "kind": "finding",
        "rule_id": str(getattr(finding, "rule_id", "") or ""),
        "severity": str(getattr(finding, "severity", "") or ""),
        "classification": str(getattr(finding, "classification", "") or ""),
        "path": str(getattr(finding, "path", "") or ""),
        "line": int(getattr(finding, "line", 0) or 0),
        "message": str(getattr(finding, "message", "") or ""),
        "scanner": str(getattr(finding, "scanner", "") or ""),
        "allowlisted": bool(getattr(finding, "allowlisted", False)),
        "confidence": _finding_confidence(finding),
    }
    for attr in ("source_status", "source_url", "source_path", "source_commit"):
        value = getattr(finding, attr, None)
        if value:
            evidence[attr] = str(value)
    return evidence


def _general_status(report: Any, findings: list[Any]) -> tuple[str, str]:
    active = [finding for finding in findings if not bool(getattr(finding, "allowlisted", False))]
    serious = [
        finding
        for finding in active
        if str(getattr(finding, "classification", "")) in {"BLOCK", "MANUAL_REVIEW"}
    ]
    if serious:
        confidence = max(
            (_finding_confidence(finding) for finding in serious),
            key=lambda value: _CONFIDENCE_RANK[value],
        )
        return "detected", confidence
    if findings:
        confidence = max(
            (_finding_confidence(finding) for finding in findings),
            key=lambda value: _CONFIDENCE_RANK[value],
        )
        return "review", confidence
    if str(getattr(report, "final_classification", "")) == "AUDIT_ERROR":
        return "unknown", "unknown"
    return "not_detected", "unknown"


def _general_summary(status: str, evidence_count: int) -> str:
    if status == "detected":
        return f"{evidence_count} reviewer signal(s) detected by current static analysis."
    if status == "review":
        return f"{evidence_count} lower-severity or allowlisted signal(s) warrant context review."
    if status == "unknown":
        return "Audit coverage was incomplete, so this question cannot be answered reliably."
    return "No matching evidence was detected by the current audit."


def _scanner_status(report: Any, name: str) -> str:
    for status in getattr(report, "scanner_statuses", []) or []:
        status_name = (
            str(status.get("name") or "")
            if isinstance(status, dict)
            else str(getattr(status, "name", "") or "")
        )
        if status_name == name:
            return (
                str(status.get("status") or "")
                if isinstance(status, dict)
                else str(getattr(status, "status", "") or "")
            )
    return ""


def _network_capability(report: Any, definition: _CapabilityDefinition) -> dict[str, Any]:
    findings = _matching_findings(report, definition)
    destinations = list(getattr(report, "network_destinations", []) or [])
    destinations.sort(
        key=lambda item: (
            -_CONFIDENCE_RANK.get(str(item.get("confidence") or "unknown"), 0),
            str(item.get("destination") or "").casefold(),
        )
    )

    evidence = [_finding_evidence(finding) for finding in findings]
    for destination in destinations:
        sources = []
        for source in (destination.get("sources") or [])[:3]:
            source_record = {
                "path": str(source.get("path") or ""),
                "line": int(source.get("line") or 0),
                "provenance": str(source.get("provenance") or ""),
                "confidence": str(source.get("confidence") or "unknown"),
            }
            for key in ("source_status", "source_url", "source_path", "source_commit"):
                if source.get(key):
                    source_record[key] = str(source[key])
            sources.append(source_record)
        evidence.append({
            "kind": "network_destination",
            "destination": str(destination.get("destination") or ""),
            "confidence": str(destination.get("confidence") or "unknown"),
            "review_priority": str(destination.get("review_priority") or ""),
            "reason": str(destination.get("reason") or ""),
            "sources": sources,
        })

    active_findings = [f for f in findings if not bool(getattr(f, "allowlisted", False))]
    serious_finding = any(
        str(getattr(f, "classification", "")) in {"BLOCK", "MANUAL_REVIEW"}
        for f in active_findings
    )
    high_destinations = sum(
        1 for item in destinations if str(item.get("confidence") or "") == "high"
    )
    medium_destinations = sum(
        1 for item in destinations if str(item.get("confidence") or "") == "medium"
    )
    low_destinations = len(destinations) - high_destinations - medium_destinations

    if serious_finding or high_destinations:
        status = "detected"
        confidence = "high"
    elif findings or destinations:
        status = "review"
        confidence = "medium" if medium_destinations or findings else "low"
    elif str(getattr(report, "final_classification", "")) == "AUDIT_ERROR":
        status, confidence = "unknown", "unknown"
    else:
        status, confidence = "not_detected", "unknown"

    if destinations:
        summary = (
            f"{len(destinations)} destination(s): {high_destinations} high-confidence runtime, "
            f"{medium_destinations} supporting, {low_destinations} inventory-only."
        )
    else:
        summary = _general_summary(status, len(findings))

    return {
        "id": definition.capability_id,
        "question": definition.question,
        "status": status,
        "confidence": confidence,
        "summary": summary,
        "evidence_count": len(evidence),
        "evidence": evidence[:_MAX_EVIDENCE],
    }


def _source_integrity_capability(
    report: Any, definition: _CapabilityDefinition
) -> dict[str, Any]:
    findings = _matching_findings(report, definition)
    diff = dict(getattr(report, "source_artifact_diff", {}) or {})
    checked = bool(diff.get("checked"))

    actionable_scripts = list(diff.get("zip_only_scripts") or [])
    actionable_executables = list(diff.get("zip_only_executables") or [])
    modified = list(diff.get("same_path_modified") or [])
    grouped = list(diff.get("grouped_packaged_outputs") or [])
    generated = list(diff.get("generated_or_dependency_differences") or [])
    other = list(diff.get("other_same_path_differences") or [])
    expected = list(diff.get("expected_build_stamp_differences") or [])

    context = {
        "kind": "source_comparison",
        "checked": checked,
        "source_commit": str(diff.get("source_commit") or ""),
        "same_path_compared": int(diff.get("same_path_compared") or 0),
        "actionable_zip_only_scripts": len(actionable_scripts),
        "actionable_zip_only_executables": len(actionable_executables),
        "same_path_modified": len(modified),
        "grouped_packaged_output_groups": len(grouped),
        "generated_or_dependency_differences": len(generated),
        "other_same_path_differences": len(other),
        "expected_build_stamp_differences": len(expected),
    }
    evidence = [context] + [_finding_evidence(finding) for finding in findings]

    active_findings = [f for f in findings if not bool(getattr(f, "allowlisted", False))]
    serious_finding = any(
        str(getattr(f, "classification", "")) in {"BLOCK", "MANUAL_REVIEW"}
        for f in active_findings
    )
    actionable_count = len(actionable_scripts) + len(actionable_executables) + len(modified)
    contextual_count = len(grouped) + len(generated) + len(other) + len(expected)

    if serious_finding or actionable_count:
        status, confidence = "detected", "high"
    elif checked and (findings or contextual_count):
        status, confidence = "review", "medium"
    elif not checked or _scanner_status(report, "source-artifact-diff") in {
        "failed",
        "unavailable",
        "unsupported",
    }:
        status, confidence = "unknown", "unknown"
    else:
        status, confidence = "not_detected", "high"

    if checked:
        summary = (
            f"Compared {context['same_path_compared']} same-path file(s); "
            f"{actionable_count} actionable difference(s), "
            f"{contextual_count} expected/grouped difference record(s)."
        )
    else:
        summary = "Exact release-to-source comparison did not complete."

    return {
        "id": definition.capability_id,
        "question": definition.question,
        "status": status,
        "confidence": confidence,
        "summary": summary,
        "evidence_count": len(evidence),
        "evidence": evidence[:_MAX_EVIDENCE],
    }


def _malware_vulnerability_capability(
    report: Any, definition: _CapabilityDefinition
) -> dict[str, Any]:
    findings = _matching_findings(report, definition)
    status, confidence = _general_status(report, findings)
    if not findings:
        scanner_states = {
            "clamav": _scanner_status(report, "clamav"),
            "trivy": _scanner_status(report, "trivy"),
        }
        incomplete = {
            name: state
            for name, state in scanner_states.items()
            if state in {"failed", "unavailable", "unsupported"}
        }
        if incomplete:
            status, confidence = "unknown", "unknown"
            summary = "Malware/vulnerability scanner coverage was incomplete: " + ", ".join(
                f"{name}={state}" for name, state in sorted(incomplete.items())
            ) + "."
        else:
            summary = _general_summary(status, 0)
    else:
        summary = _general_summary(status, len(findings))

    evidence = [_finding_evidence(finding) for finding in findings]
    return {
        "id": definition.capability_id,
        "question": definition.question,
        "status": status,
        "confidence": confidence,
        "summary": summary,
        "evidence_count": len(evidence),
        "evidence": evidence[:_MAX_EVIDENCE],
    }


def _generic_capability(report: Any, definition: _CapabilityDefinition) -> dict[str, Any]:
    findings = _matching_findings(report, definition)
    status, confidence = _general_status(report, findings)
    evidence = [_finding_evidence(finding) for finding in findings]
    return {
        "id": definition.capability_id,
        "question": definition.question,
        "status": status,
        "confidence": confidence,
        "summary": _general_summary(status, len(evidence)),
        "evidence_count": len(evidence),
        "evidence": evidence[:_MAX_EVIDENCE],
    }


def build_reviewer_capabilities(report: Any) -> dict[str, Any]:
    """Return the deterministic, versioned reviewer capability summary."""
    items: list[dict[str, Any]] = []
    for definition in _CAPABILITIES:
        if definition.capability_id == "network_communication":
            item = _network_capability(report, definition)
        elif definition.capability_id == "release_source_integrity":
            item = _source_integrity_capability(report, definition)
        elif definition.capability_id == "malware_or_known_vulnerabilities":
            item = _malware_vulnerability_capability(report, definition)
        else:
            item = _generic_capability(report, definition)
        items.append(item)
    return {
        "schema_version": _CAPABILITY_SCHEMA_VERSION,
        "items": items,
    }


def _markdown_location(evidence: dict[str, Any]) -> str:
    path = str(evidence.get("path") or "")
    line = int(evidence.get("line") or 0)
    if not path:
        return ""
    label = f"`{path}:{line}`" if line else f"`{path}`"
    source_url = str(evidence.get("source_url") or "")
    return f"[{label}]({source_url})" if source_url else label


def _render_evidence(evidence: dict[str, Any]) -> str:
    kind = str(evidence.get("kind") or "")
    if kind == "finding":
        location = _markdown_location(evidence)
        location_text = f" {location}" if location else ""
        allowlisted = " _(allowlisted)_" if evidence.get("allowlisted") else ""
        return (
            f"- **{evidence.get('rule_id', 'UNKNOWN')}**{location_text} — "
            f"{evidence.get('message', '')}{allowlisted}"
        )
    if kind == "network_destination":
        destination = str(evidence.get("destination") or "unknown")
        confidence = str(evidence.get("confidence") or "unknown")
        sources = list(evidence.get("sources") or [])
        suffix = ""
        if sources:
            source = sources[0]
            source_url = str(source.get("source_url") or "")
            source_path = str(source.get("path") or "")
            source_line = int(source.get("line") or 0)
            source_label = f"`{source_path}:{source_line}`" if source_line else f"`{source_path}`"
            if source_url:
                source_label = f"[{source_label}]({source_url})"
            suffix = f" — example source {source_label}"
        return f"- `{destination}` — {confidence} confidence{suffix}"
    if kind == "source_comparison":
        return (
            "- Exact source comparison — "
            f"{evidence.get('same_path_compared', 0)} same-path files compared; "
            f"{evidence.get('actionable_zip_only_scripts', 0)} unexpected scripts; "
            f"{evidence.get('actionable_zip_only_executables', 0)} unexpected executables; "
            f"{evidence.get('same_path_modified', 0)} security-relevant mismatches."
        )
    return "- Reviewer evidence available in the JSON report."


def render_reviewer_capabilities(summary: dict[str, Any]) -> str:
    """Render a compact Markdown overview plus bounded evidence details."""
    items = list(summary.get("items") or [])
    if not items:
        return ""

    lines = [
        "## Reviewer Capability Summary",
        "",
        (
            "_Derived from existing audit evidence. This reviewer aid does not change "
            "classification, risk score, allowlisting, or scanner policy. "
            "\"No evidence\" means only that the current static audit did not detect a matching signal._"
        ),
        "",
        "| Status | Reviewer question | Confidence | Signals |",
        "|---|---|---|---:|",
    ]
    for item in items:
        status = str(item.get("status") or "unknown")
        label = _STATUS_LABELS.get(status, status.upper())
        icon = _STATUS_ICONS.get(status, "❓")
        confidence = str(item.get("confidence") or "unknown")
        lines.append(
            f"| {icon} **{label}** | {item.get('question', '')} | {confidence} | "
            f"{int(item.get('evidence_count') or 0)} |"
        )
    lines.append("")

    for item in items:
        status = str(item.get("status") or "unknown")
        if status == "not_detected":
            continue
        open_attr = " open" if status in {"detected", "unknown"} else ""
        lines += [
            f"<details{open_attr}>",
            (
                f"<summary>{_STATUS_ICONS.get(status, '❓')} "
                f"{item.get('question', '')} — "
                f"{_STATUS_LABELS.get(status, status.upper())}</summary>"
            ),
            "",
            str(item.get("summary") or ""),
            "",
        ]
        evidence = list(item.get("evidence") or [])
        if evidence:
            lines.extend(_render_evidence(record) for record in evidence)
            total = int(item.get("evidence_count") or len(evidence))
            if total > len(evidence):
                lines.append(
                    f"- _{total - len(evidence)} additional signal(s) remain in the raw report._"
                )
        lines += ["", "</details>", ""]

    return "\n".join(lines).rstrip() + "\n"


def _inject_capability_section(markdown: str, summary: dict[str, Any]) -> str:
    if "## Reviewer Capability Summary" in markdown:
        return markdown
    section = render_reviewer_capabilities(summary)
    if not section:
        return markdown

    marker = "### Blocking Findings"
    if marker in markdown:
        return markdown.replace(marker, section + "\n" + marker, 1)
    return markdown.rstrip() + "\n\n" + section


def install(core: ModuleType) -> ModuleType:
    """Install capability derivation and Markdown reporting on the audit core."""
    if getattr(core, "_reviewer_capability_summaries_installed", False):
        return core

    base_report = core.AuditReport
    if "reviewer_capabilities" not in getattr(base_report, "__dataclass_fields__", {}):
        capability_report = make_dataclass(
            "AuditReport",
            [
                (
                    "reviewer_capabilities",
                    dict[str, Any],
                    field(default_factory=dict),
                )
            ],
            bases=(base_report,),
        )
        capability_report.__module__ = base_report.__module__
        core.AuditReport = capability_report

    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_generate_markdown: Callable[[Any], str] = core.generate_markdown_report

    def audit_repository(*args: Any, **kwargs: Any) -> Any:
        report = raw_audit_repository(*args, **kwargs)
        report.reviewer_capabilities = build_reviewer_capabilities(report)
        return report

    def generate_markdown_report(report: Any) -> str:
        summary = dict(getattr(report, "reviewer_capabilities", {}) or {})
        if not summary.get("items"):
            summary = build_reviewer_capabilities(report)
            report.reviewer_capabilities = summary
        markdown = raw_generate_markdown(report)
        return _inject_capability_section(markdown, summary)

    core.audit_repository = audit_repository
    core.generate_markdown_report = generate_markdown_report
    core.build_reviewer_capabilities = build_reviewer_capabilities
    core.render_reviewer_capabilities = render_reviewer_capabilities
    core._reviewer_capability_summaries_installed = True
    return core
