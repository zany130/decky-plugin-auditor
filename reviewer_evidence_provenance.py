"""Add trustworthy provenance to reviewer capability evidence."""

from __future__ import annotations

import re
from types import ModuleType
from typing import Any, Callable
from urllib.parse import quote, urlparse

import reviewer_capabilities as reviewer

_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_BLOB_PATH = re.compile(r"^/([^/]+)/([^/]+)/blob/([0-9a-fA-F]{40})/(.+)$")
_DIFF_KEYS = (
    "same_path_modified",
    "generated_or_dependency_differences",
    "other_same_path_differences",
    "expected_build_stamp_differences",
)
_RELEASE_ONLY_DIFFS = {
    "zip_only_executables",
    "zip_only_scripts",
    "large_binaries_absent_from_source",
}
_SECRET_PATTERNS = (
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._-]{20,}\b"),
)


def _value(item: object, name: str, default: Any = None) -> Any:
    return item.get(name, default) if isinstance(item, dict) else getattr(item, name, default)


def _redact(value: object) -> str:
    text = str(value or "")
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[REDACTED]", text)
    return text


def _md(value: object) -> str:
    text = " ".join(_redact(value).splitlines()).replace("\\", "\\\\")
    for char in ("`", "[", "]", "(", ")", "<", ">"):
        text = text.replace(char, f"\\{char}")
    return text


def _code(value: object) -> str:
    text = " ".join(_redact(value).splitlines()) or "<none>"
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(1, longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text}{pad}{fence}"


def _path_keys(path: str) -> set[str]:
    path = path.replace("\\", "/").strip().lstrip("./").strip("/")
    if not path:
        return set()
    keys = {path.casefold()}
    if "/" in path:
        keys.add(path.split("/", 1)[1].casefold())
    return keys


def _differing_paths(report: object) -> set[str]:
    diff = dict(getattr(report, "source_artifact_diff", {}) or {})
    paths: set[str] = set()
    for key in _DIFF_KEYS:
        for record in diff.get(key) or []:
            if isinstance(record, dict):
                paths.update(_path_keys(str(record.get("artifact_path") or "")))
    return paths


def _repo_parts(report: object) -> tuple[str, str]:
    value = str(getattr(report, "repository", "") or "").strip().rstrip("/")
    if not value:
        return "", ""
    parsed = urlparse(value if "://" in value else f"https://github.com/{value}")
    if parsed.scheme != "https" or parsed.hostname != "github.com":
        return "", ""
    parts = [part for part in parsed.path.split("/") if part]
    return (parts[0], parts[1]) if len(parts) >= 2 else ("", "")


def _sha(value: object) -> str:
    value = str(value or "")
    return value if _FULL_SHA.fullmatch(value) else ""


def _source_url(report: object, commit: str, path: str, line: int = 0) -> str:
    owner, repo = _repo_parts(report)
    commit = _sha(commit)
    raw_path = str(path or "")
    if not owner or not repo or not commit or not raw_path or _redact(raw_path) != raw_path:
        return ""
    encoded = quote(raw_path.replace("\\", "/").lstrip("./").strip("/"), safe="/")
    url = f"https://github.com/{owner}/{repo}/blob/{commit}/{encoded}"
    return url + (f"#L{line}" if line > 0 else "")


def _validated_url(url: object, commit: object) -> str:
    value, commit = str(url or ""), _sha(commit)
    if not value or not commit:
        return ""
    parsed = urlparse(value)
    if parsed.scheme != "https" or parsed.hostname != "github.com" or parsed.query:
        return ""
    match = _BLOB_PATH.fullmatch(parsed.path)
    if not match or match.group(3).lower() != commit.lower():
        return ""
    if parsed.fragment and not re.fullmatch(r"L\d+(?:-L\d+)?", parsed.fragment):
        return ""
    return value


def _without_fragment(url: str) -> str:
    return urlparse(url)._replace(fragment="").geturl()


def _context(finding: object) -> str:
    rule, scanner = reviewer._rule_key(finding), reviewer._scanner_key(finding)
    tokens = set(rule.split("_")) if rule else set()
    if rule == "MALWARE" or scanner == "clamav":
        return "malware scanner finding"
    if scanner in {"trivy", "osv", "osv-scanner"} or "CVE" in tokens:
        return "known vulnerable component reported"
    if rule.startswith("PRIVILEGE_SUDO") or "SUDO" in tokens:
        return "sudo or elevated command usage"
    if rule == "ROOT_ACCESS":
        return "root-level access behavior"
    if rule.startswith("PRIVILEGE_"):
        return "privileged system operation"
    if rule.startswith("PERSIST_"):
        return "persistence or startup behavior"
    if "SUBPROCESS" in tokens or rule.startswith("EXEC_"):
        return "command or subprocess execution"
    if "SHELL" in tokens or "CURL_PIPE" in rule:
        return "shell command execution"
    if rule.startswith(("SENSITIVE_", "CREDENTIAL_")) or "SECRET" in tokens:
        return "sensitive-data or credential access"
    if rule.startswith("NETWORK_") or "HTTP_REQUEST" in rule or "WEBSOCKET" in rule:
        return "network communication behavior"
    if "NATIVE_BINARY" in rule or rule.startswith("BINARY_"):
        return "native executable content"
    if rule.startswith("ZIP_ONLY_") or "SOURCE_ARTIFACT" in rule:
        return "published release/source difference"
    return f"{scanner} security finding" if scanner else "security finding"


def _provenance(item: object, report: object, *, network: bool = False) -> dict[str, Any]:
    status = str(_value(item, "source_status", "") or "")
    source_path_raw = str(_value(item, "source_path", "") or "")
    source_path = _redact(source_path_raw)
    raw_commit = str(_value(item, "source_commit", "") or getattr(report, "source_commit", "") or "")
    commit = _sha(raw_commit)
    raw_url = str(_value(item, "source_url", "") or "")
    line = int(_value(item, "line", 0) or 0)
    exact = bool(_value(item, "source_line_exact", False))
    note = _redact(_value(item, "source_note", "") or "")

    if not network and status == "linked" and not exact:
        checked = bool(dict(getattr(report, "source_artifact_diff", {}) or {}).get("checked"))
        differs = bool(_path_keys(str(_value(item, "path", "") or "")) & _differing_paths(report))
        if reviewer._scanner_key(item) != "semgrep" and checked and not differs:
            exact = line > 0
        elif not note:
            note = (
                "release contents differ from tagged source; artifact line is not exact"
                if differs
                else "same-path source contents were not verified; artifact line is not exact"
            )

    immutable = ""
    if status in {"linked", "file-only"} and source_path_raw == source_path:
        wanted_line = line if status == "linked" and exact else 0
        immutable = _source_url(report, commit, source_path_raw, wanted_line)
        if not immutable:
            candidate = _validated_url(raw_url, commit)
            if candidate:
                immutable = candidate if wanted_line else _without_fragment(candidate)

    record: dict[str, Any] = {}
    if status:
        record["source_status"] = status
    if source_path:
        record["source_path"] = source_path
    if raw_commit:
        record["source_commit"] = raw_commit
    if raw_url:
        record["source_url"] = raw_url
    if immutable:
        record["immutable_source_url"] = immutable
    if status in {"linked", "file-only"}:
        record["source_line_exact"] = bool(exact and status == "linked")
    if note:
        record["source_note"] = note
    return record


def _finding_evidence(finding: object, report: object) -> dict[str, Any]:
    data = reviewer._finding_evidence(finding)
    data["context"] = _context(finding)
    data["path"] = _redact(data.get("path", ""))
    data.update(_provenance(finding, report))
    return data


def _network_evidence(report: object) -> list[tuple[dict[str, Any], str]]:
    destinations = list(getattr(report, "network_destinations", []) or [])
    if not destinations:
        return reviewer._network_evidence(report)
    destinations.sort(key=lambda item: (
        -reviewer._CONFIDENCE_RANK.get(str(_value(item, "confidence", "unknown") or "unknown"), 0),
        str(_value(item, "destination", "") or "").casefold(),
    ))
    result = []
    for item in destinations:
        confidence = str(_value(item, "confidence", "low") or "low")
        sources = []
        for source in list(_value(item, "sources", []) or []):
            record = {
                "path": _redact(_value(source, "path", "") or ""),
                "line": int(_value(source, "line", 0) or 0),
                "provenance": _redact(_value(source, "provenance", "") or ""),
                "confidence": str(_value(source, "confidence", "unknown") or "unknown"),
            }
            record.update(_provenance(source, report, network=True))
            sources.append(record)
        sources.sort(key=lambda source: (
            source.get("path", ""), int(source.get("line", 0) or 0),
            source.get("provenance", ""), source.get("immutable_source_url", source.get("source_url", "")),
        ))
        result.append(({
            "kind": "network_destination",
            "destination": _redact(_value(item, "destination", "") or ""),
            "confidence": confidence,
            "review_priority": str(_value(item, "review_priority", "") or ""),
            "reason": _redact(_value(item, "reason", "") or ""),
            "sources": sources[:3],
        }, confidence if confidence in reviewer._CONFIDENCE_RANK else "low"))
    return result


def _source_sample(report: object, category: str, value: object) -> dict[str, Any] | None:
    if isinstance(value, dict):
        artifact = str(value.get("artifact_path") or value.get("path") or value.get("source_path") or "")
        source = str(value.get("source_path") or "")
    else:
        artifact, source = str(value or ""), ""
    if not artifact:
        return None
    sample: dict[str, Any] = {"artifact_path": _redact(artifact)}
    if source:
        sample["source_path"] = _redact(source)
    if category in _RELEASE_ONLY_DIFFS or not source:
        sample["source_status"] = "release-only"
        return sample
    commit = _sha(getattr(report, "source_commit", ""))
    url = _source_url(report, commit, source)
    if url:
        sample.update({
            "source_status": "file-only", "source_commit": commit,
            "source_url": url, "immutable_source_url": url, "source_line_exact": False,
        })
        if category == "same_path_modified":
            sample["source_note"] = "release contents differ from tagged source; upstream file shown without a line claim"
    else:
        sample["source_status"] = "unresolved"
    return sample


def _source_evidence(report: object) -> list[tuple[dict[str, Any], str]]:
    diff = dict(getattr(report, "source_artifact_diff", {}) or {})
    if not diff.get("checked"):
        return []
    categories = (
        ("zip_only_executables", "high"), ("zip_only_scripts", "high"),
        ("large_binaries_absent_from_source", "high"), ("unexpected_urls", "high"),
        ("same_path_modified", "high"), ("grouped_packaged_outputs", "low"),
        ("generated_or_dependency_differences", "low"),
        ("other_same_path_differences", "low"), ("expected_build_stamp_differences", "low"),
    )
    result = []
    for category, confidence in categories:
        values = list(diff.get(category) or [])
        if not values:
            continue
        samples: dict[str, dict[str, Any]] = {}
        for value in values:
            sample = _source_sample(report, category, value)
            if not sample:
                continue
            path = str(sample["artifact_path"])
            if path in samples:
                continue
            if len(samples) < 5:
                samples[path] = sample
            elif path < max(samples):
                del samples[max(samples)]
                samples[path] = sample
        ordered = [samples[path] for path in sorted(samples)]
        result.append(({
            "kind": "source_artifact_diff", "category": category, "count": len(values),
            "sample_paths": [sample["artifact_path"] for sample in ordered], "samples": ordered,
        }, confidence))
    return result


def _structured(capability_id: str, report: object) -> list[tuple[dict[str, Any], str]]:
    if capability_id == "network_communication":
        return _network_evidence(report)
    if capability_id == "source_release_integrity":
        return _source_evidence(report)
    structured = reviewer._structured_evidence(capability_id, report)
    for item, _confidence in structured:
        for key in ("path", "label", "architecture"):
            if key in item:
                item[key] = _redact(item[key])
    return structured


def _finding_key(item: dict[str, Any]) -> tuple[Any, ...]:
    return (
        item.get("rule_id", ""), item.get("severity", ""), item.get("classification", ""),
        item.get("scanner", ""), item.get("path", ""), int(item.get("line", 0) or 0),
        item.get("source_status", ""), item.get("immutable_source_url", item.get("source_url", "")),
        bool(item.get("allowlisted")),
    )


def summarize_reviewer_capabilities(report: object) -> list[dict[str, Any]]:
    findings = list(getattr(report, "findings", []) or [])
    capabilities = []
    for spec in reviewer._CAPABILITIES:
        matched = sorted(
            [f for f in findings if reviewer._matches_finding(spec.capability_id, f)],
            key=reviewer._finding_sort_key,
        )
        evidence: list[dict[str, Any]] = []
        confidences: list[str] = []
        structured = _structured(spec.capability_id, report)
        for item, confidence in structured:
            if len(evidence) < reviewer._MAX_EVIDENCE_PER_CAPABILITY:
                evidence.append(item)
            confidences.append(confidence)

        distinct_findings = collapsed = 0
        previous = None
        for finding in matched:
            item = _finding_evidence(finding, report)
            key = _finding_key(item)
            if key == previous:
                collapsed += 1
            else:
                distinct_findings += 1
                if len(evidence) < reviewer._MAX_EVIDENCE_PER_CAPABILITY:
                    evidence.append(item)
                previous = key
            confidences.append(reviewer._finding_confidence(finding))

        total, distinct_total = len(matched) + len(structured), distinct_findings + len(structured)
        substantive = total > 0
        if spec.capability_id == "source_release_integrity":
            substantive = bool(structured) or any(
                reviewer._rule_key(f) != "SOURCE_ARTIFACT_DIFF_INCOMPLETE" for f in matched
            )
        status, reason = (
            ("observed", "Supporting audit evidence was found.")
            if substantive
            else reviewer._status_without_evidence(spec.capability_id, report)
        )
        capabilities.append({
            "id": spec.capability_id, "title": spec.title, "question": spec.question,
            "status": status, "status_reason": reason,
            "confidence": reviewer._max_confidence(confidences),
            "finding_count": len(matched), "evidence_count": total,
            "distinct_evidence_count": distinct_total, "evidence_collapsed": collapsed,
            "rule_ids": sorted({str(_value(f, "rule_id", "") or "") for f in matched if _value(f, "rule_id", "")}),
            "evidence": evidence,
            "evidence_truncated": distinct_total > reviewer._MAX_EVIDENCE_PER_CAPABILITY,
        })
    return capabilities


def _provenance_suffix(item: dict[str, Any]) -> str:
    status = str(item.get("source_status") or "")
    url = str(item.get("immutable_source_url") or "")
    note = str(item.get("source_note") or "")
    if status == "linked" and url and item.get("source_line_exact"):
        return f" — [immutable upstream source]({url})"
    if status in {"linked", "file-only"} and url:
        return f" — [tagged source file]({url}) _({_md(note or 'tagged source file linked; artifact line is not exact')})_"
    messages = {
        "release-only": "release-only; no upstream source file",
        "unmapped": "tagged-source path could not be mapped",
        "unresolved": "immutable upstream source could not be resolved",
        "not-applicable": "upstream source link not applicable",
    }
    if status in messages:
        return f" _({messages[status]})_"
    if status in {"linked", "file-only"}:
        return " _(immutable upstream source link unavailable)_"
    return ""


def _render_evidence(item: dict[str, Any]) -> str:
    kind = item.get("kind")
    if kind == "finding":
        path, line = str(item.get("path") or ""), int(item.get("line") or 0)
        location = _code(f"{path}:{line}" if path and line else path) if path else "report-level evidence"
        allowlisted = " — **allowlisted for enforcement; capability still present**" if item.get("allowlisted") else ""
        return f"{_code(item.get('rule_id'))} — {_md(item.get('context') or 'security finding')} at {location}{_provenance_suffix(item)}{allowlisted}"
    if kind == "network_destination":
        text = f"network destination {_code(item.get('destination'))} — {_md(item.get('confidence', 'low'))} confidence; {_md(item.get('reason') or 'network reference')}"
        sources = list(item.get("sources") or [])
        if sources:
            refs = []
            for source in sources[:3]:
                path, line = str(source.get("path") or ""), int(source.get("line") or 0)
                refs.append(_code(f"{path}:{line}" if path and line else path) + _provenance_suffix(source))
            text += "; sources: " + ", ".join(refs)
        return text
    if kind == "native_binary":
        details = _md(item.get("label") or "native binary")
        if item.get("architecture"):
            details += f", {_md(item.get('architecture'))}"
        return f"native binary {_code(item.get('path'))} — {details}"
    if kind == "source_artifact_diff":
        samples = list(item.get("samples") or [])
        rendered = [
            _code(sample.get("artifact_path") or "") + _provenance_suffix(sample)
            for sample in samples[:3]
        ] or [_code(path) for path in list(item.get("sample_paths") or [])[:3]]
        suffix = f"; examples: {', '.join(rendered)}" if rendered else ""
        return f"source/artifact {_code(item.get('category'))} — {item.get('count', 0)} item(s){suffix}"
    return _md(item)


def _identity(report: object) -> list[str]:
    repository = str(getattr(report, "repository", "") or "")
    release = str(getattr(report, "release", "") or "")
    artifact = str(getattr(report, "artifact_sha256", "") or "")
    commit = _sha(getattr(report, "source_commit", ""))
    owner, repo = _repo_parts(report)
    commit_value = (
        f"[{commit[:12]}](https://github.com/{owner}/{repo}/commit/{commit})"
        if commit and owner and repo
        else "not resolved"
    )
    checked = bool(dict(getattr(report, "source_artifact_diff", {}) or {}).get("checked"))
    return [
        "### Audit identity", "",
        f"- Repository: {_code(repository or 'not recorded')}",
        f"- Release: {_code(release or 'not recorded')}",
        f"- Artifact SHA-256: {_code(artifact or 'not recorded')}",
        f"- Tagged source commit: {commit_value}",
        f"- Exact release/source comparison: {_code('completed' if checked else 'incomplete')}", "",
    ]


def render_reviewer_capabilities(capabilities: list[dict[str, Any]], report: object | None = None) -> str:
    lines = [
        "## Reviewer Capability Summary", "",
        "> **Interpretation:** `not_observed` means relevant audit coverage completed without supporting evidence. `unknown` means coverage was incomplete or unavailable. Neither status proves that a capability is impossible. Upstream links are commit-pinned; a line anchor is shown only when the summary can treat that source line as exact.", "",
    ]
    if report is not None:
        lines.extend(_identity(report))
    lines.extend(["| Reviewer question | Status | Confidence | Evidence |", "|---|---|---|---:|"])
    icons = {"observed": "🔎", "not_observed": "➖", "unknown": "❓"}
    for cap in capabilities:
        status, confidence = str(cap.get("status") or "unknown"), str(cap.get("confidence") or "none")
        distinct, total = int(cap.get("distinct_evidence_count", cap.get("evidence_count", 0)) or 0), int(cap.get("evidence_count", 0) or 0)
        count = str(distinct) if distinct == total else f"{distinct} distinct / {total} total"
        lines.append(f"| {cap.get('question')} | {icons.get(status, '❓')} `{status}` | `{confidence}` | {count} |")
    for cap in [c for c in capabilities if c.get("status") in {"observed", "unknown"}]:
        lines.extend(["", f"### {cap.get('title')}", "", f"**Question:** {cap.get('question')}", ""])
        if cap.get("status") == "unknown":
            lines.extend([f"**Coverage:** {cap.get('status_reason', 'Coverage is incomplete.')}", ""])
        evidence = list(cap.get("evidence") or [])
        lines.extend(f"- {_render_evidence(item)}" for item in evidence)
        if cap.get("evidence_collapsed"):
            lines.append(f"- _{int(cap['evidence_collapsed'])} duplicate finding evidence item(s) were collapsed in this summary._")
        if cap.get("evidence_truncated"):
            distinct = int(cap.get("distinct_evidence_count", cap.get("evidence_count", 0)) or 0)
            lines.append(f"- _{max(0, distinct - len(evidence))} additional distinct evidence item(s) remain available in the raw findings/structured report data._")
    return "\n".join(lines).rstrip()


def _inject_identity(markdown: str, report: object) -> str:
    if "### Audit identity" in markdown:
        return markdown
    marker = "## Reviewer Capability Summary\n\n"
    if marker not in markdown:
        return markdown
    return markdown.replace(marker, marker + "\n".join(_identity(report)) + "\n", 1)


def install(core: ModuleType) -> ModuleType:
    if getattr(core, "_reviewer_evidence_provenance_installed", False):
        return core
    if not getattr(core, "_reviewer_capabilities_installed", False):
        raise RuntimeError("reviewer_capabilities must be installed first")
    reviewer.summarize_reviewer_capabilities = summarize_reviewer_capabilities
    reviewer.render_reviewer_capabilities = render_reviewer_capabilities
    core.summarize_reviewer_capabilities = summarize_reviewer_capabilities
    core.render_reviewer_capabilities = render_reviewer_capabilities
    raw_markdown: Callable[[Any], str] = core.generate_markdown_report

    def generate_markdown_report(report: Any) -> str:
        return _inject_identity(raw_markdown(report), report)

    core.generate_markdown_report = generate_markdown_report
    core._reviewer_evidence_provenance_installed = True
    return core
