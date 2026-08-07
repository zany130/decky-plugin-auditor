"""Keep reviewer capability source links consistent with exact-source evidence.

Capability summaries reuse source links attached to raw findings. When an
artifact path is known to differ from the tagged source, an artifact line must
not be presented as an exact source line. The existing network provenance layer
already makes this distinction; this module applies the same rule to capability
finding evidence without changing the underlying audit finding or security
classification.
"""

from __future__ import annotations

from pathlib import PurePosixPath
from types import ModuleType
from typing import Any, Callable
from urllib.parse import urldefrag

_SOURCE_DIFFERENCE_KEYS = (
    "same_path_modified",
    "generated_or_dependency_differences",
    "other_same_path_differences",
    "expected_build_stamp_differences",
)


def _normalise_path(path: str) -> str:
    value = path.replace("\\", "/").strip()
    while value.startswith("./"):
        value = value[2:]
    return PurePosixPath(value).as_posix().strip("/").casefold() if value else ""


def _path_keys(path: str) -> set[str]:
    normalised = _normalise_path(path)
    if not normalised:
        return set()
    keys = {normalised}
    if "/" in normalised:
        keys.add(normalised.split("/", 1)[1])
    return keys


def _differing_paths(report: Any) -> set[str]:
    summary = dict(getattr(report, "source_artifact_diff", {}) or {})
    paths: set[str] = set()
    for key in _SOURCE_DIFFERENCE_KEYS:
        for record in summary.get(key) or []:
            if not isinstance(record, dict):
                continue
            paths.update(_path_keys(str(record.get("artifact_path") or "")))
            paths.update(_path_keys(str(record.get("source_path") or "")))
    return paths


def harden_capability_source_links(report: Any, summary: dict[str, Any]) -> dict[str, Any]:
    """Remove false exact-line claims from capability finding evidence."""
    differing = _differing_paths(report)
    if not differing:
        return summary

    for item in summary.get("items") or []:
        for evidence in item.get("evidence") or []:
            if evidence.get("kind") != "finding":
                continue
            if not (_path_keys(str(evidence.get("path") or "")) & differing):
                continue
            source_url = str(evidence.get("source_url") or "")
            if source_url:
                evidence["source_url"] = urldefrag(source_url).url
            evidence["source_line_exact"] = False
            evidence["source_note"] = (
                "release contents differ from tagged source; artifact line is not exact"
            )
    return summary


def install(core: ModuleType) -> ModuleType:
    """Install capability-source-link hardening after capability derivation."""
    if getattr(core, "_reviewer_capability_source_hardening_installed", False):
        return core
    if not getattr(core, "_reviewer_capability_summaries_installed", False):
        raise RuntimeError("reviewer_capability_summaries must be installed first")

    raw_audit_repository: Callable[..., Any] = core.audit_repository
    raw_generate_markdown: Callable[[Any], str] = core.generate_markdown_report

    def _rebuild(report: Any) -> dict[str, Any]:
        # Direct report rendering can bypass audit_repository. Enrich first so
        # capability evidence receives the same immutable source links as the
        # raw report before the summary is rendered.
        if (
            not getattr(report, "_source_links_enriched", False)
            and hasattr(core, "enrich_report_source_links")
        ):
            core.enrich_report_source_links(report)
        summary = core.build_reviewer_capabilities(report)
        summary = harden_capability_source_links(report, summary)
        report.reviewer_capabilities = summary
        return summary

    def audit_repository(*args: Any, **kwargs: Any) -> Any:
        report = raw_audit_repository(*args, **kwargs)
        _rebuild(report)
        return report

    def generate_markdown_report(report: Any) -> str:
        _rebuild(report)
        return raw_generate_markdown(report)

    core.audit_repository = audit_repository
    core.generate_markdown_report = generate_markdown_report
    core.harden_capability_source_links = harden_capability_source_links
    core._reviewer_capability_source_hardening_installed = True
    return core
