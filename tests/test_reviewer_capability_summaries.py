"""Tests for the additive reviewer-oriented capability summary layer."""

from __future__ import annotations

import unittest

import audit_plugins as ap
import reviewer_capability_summaries as capabilities


class ReviewerCapabilitySummaryTests(unittest.TestCase):
    def _report(self, classification: str = "MANUAL_REVIEW") -> ap.AuditReport:
        return ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1.0.0",
            plugin_name="Example Plugin",
            final_classification=classification,
            risk_score=42,
        )

    def _finding(
        self,
        rule_id: str,
        *,
        severity: str = "high",
        classification: str = "MANUAL_REVIEW",
        path: str = "main.py",
        line: int = 10,
        scanner: str = "decky-static-rules",
        allowlisted: bool = False,
    ) -> ap.Finding:
        finding = ap.Finding(
            rule_id=rule_id,
            severity=severity,
            classification=classification,
            path=path,
            line=line,
            message=f"Evidence for {rule_id}",
            evidence="bounded evidence",
            scanner=scanner,
            allowlisted=allowlisted,
        )
        return finding

    @staticmethod
    def _items(summary: dict) -> dict[str, dict]:
        return {item["id"]: item for item in summary["items"]}

    def test_maps_existing_findings_without_changing_security_result(self) -> None:
        report = self._report()
        original_classification = report.final_classification
        original_score = report.risk_score
        report.findings = [
            self._finding("EXEC_OS_SYSTEM"),
            self._finding("ROOT_ACCESS"),
            self._finding("SENSITIVE_SSH_KEY"),
            self._finding(
                "SECRET_BEARER_TOKEN",
                severity="low",
                classification="PASS_WITH_WARNINGS",
                scanner="credential-exposure-scanner",
            ),
            self._finding("NATIVE_BINARY", scanner="binary-detector"),
        ]

        summary = capabilities.build_reviewer_capabilities(report)
        items = self._items(summary)

        self.assertEqual(summary["schema_version"], "1")
        self.assertEqual(items["command_execution"]["status"], "detected")
        self.assertEqual(items["elevated_privileges"]["status"], "detected")
        self.assertEqual(items["sensitive_data_access"]["status"], "detected")
        self.assertEqual(items["embedded_credentials"]["status"], "review")
        self.assertEqual(items["native_or_opaque_code"]["status"], "detected")
        self.assertEqual(report.final_classification, original_classification)
        self.assertEqual(report.risk_score, original_score)

    def test_high_confidence_runtime_destination_is_detected(self) -> None:
        report = self._report("PASS")
        report.network_destinations = [
            {
                "destination": "api.example.com",
                "confidence": "high",
                "review_priority": "primary",
                "reason": "referenced by plugin-owned runtime code",
                "sources": [
                    {
                        "path": "main.py",
                        "line": 20,
                        "provenance": "plugin_runtime",
                        "confidence": "high",
                        "source_url": "https://github.com/example/plugin/blob/abc/main.py#L20",
                    }
                ],
            }
        ]

        item = self._items(capabilities.build_reviewer_capabilities(report))[
            "network_communication"
        ]

        self.assertEqual(item["status"], "detected")
        self.assertEqual(item["confidence"], "high")
        self.assertEqual(item["evidence"][0]["kind"], "network_destination")
        self.assertIn("1 destination", item["summary"])

    def test_low_confidence_network_inventory_requires_context_review(self) -> None:
        report = self._report("PASS")
        report.network_destinations = [
            {
                "destination": "docs.example.com",
                "confidence": "low",
                "review_priority": "inventory",
                "reason": "reference-only or dependency/build evidence",
                "sources": [],
            }
        ]

        item = self._items(capabilities.build_reviewer_capabilities(report))[
            "network_communication"
        ]

        self.assertEqual(item["status"], "review")
        self.assertEqual(item["confidence"], "low")

    def test_exact_source_comparison_distinguishes_clean_and_actionable_results(self) -> None:
        clean = self._report("PASS")
        clean.source_artifact_diff = {
            "checked": True,
            "source_commit": "abc123",
            "same_path_compared": 12,
            "zip_only_scripts": [],
            "zip_only_executables": [],
            "same_path_modified": [],
            "grouped_packaged_outputs": [],
            "generated_or_dependency_differences": [],
            "other_same_path_differences": [],
            "expected_build_stamp_differences": [],
        }
        clean_item = self._items(capabilities.build_reviewer_capabilities(clean))[
            "release_source_integrity"
        ]
        self.assertEqual(clean_item["status"], "not_detected")
        self.assertEqual(clean_item["confidence"], "high")

        changed = self._report()
        changed.source_artifact_diff = {
            "checked": True,
            "source_commit": "abc123",
            "same_path_compared": 12,
            "zip_only_scripts": ["Plugin/runtime.sh"],
            "zip_only_executables": [],
            "same_path_modified": [],
        }
        changed.findings = [
            self._finding(
                "ZIP_ONLY_SCRIPT",
                path="Plugin/runtime.sh",
                line=0,
                scanner="source-artifact-diff",
            )
        ]
        changed_item = self._items(capabilities.build_reviewer_capabilities(changed))[
            "release_source_integrity"
        ]
        self.assertEqual(changed_item["status"], "detected")
        self.assertEqual(changed_item["confidence"], "high")

    def test_incomplete_security_scanners_produce_unknown_not_false_clean(self) -> None:
        report = self._report("PASS")
        report.scanner_statuses = [
            ap.ScannerStatus(name="clamav", status="passed"),
            ap.ScannerStatus(name="trivy", status="unavailable"),
        ]

        item = self._items(capabilities.build_reviewer_capabilities(report))[
            "malware_or_known_vulnerabilities"
        ]

        self.assertEqual(item["status"], "unknown")
        self.assertIn("trivy=unavailable", item["summary"])

    def test_evidence_is_bounded_but_total_count_is_preserved(self) -> None:
        report = self._report()
        report.findings = [
            self._finding("EXEC_OS_SYSTEM", path=f"module_{index}.py", line=index + 1)
            for index in range(12)
        ]

        item = self._items(capabilities.build_reviewer_capabilities(report))[
            "command_execution"
        ]

        self.assertEqual(item["evidence_count"], 12)
        self.assertEqual(len(item["evidence"]), 8)

    def test_installed_report_schema_serializes_capability_summary(self) -> None:
        self.assertIn("reviewer_capabilities", ap.AuditReport.__dataclass_fields__)
        report = self._report("PASS")
        report.reviewer_capabilities = capabilities.build_reviewer_capabilities(report)

        data = ap._report_to_dict(report)

        self.assertEqual(data["reviewer_capabilities"]["schema_version"], "1")
        self.assertEqual(len(data["reviewer_capabilities"]["items"]), 10)

    def test_markdown_summary_explains_additive_semantics_and_links_evidence(self) -> None:
        report = self._report()
        finding = self._finding("EXEC_OS_SYSTEM")
        finding.source_url = "https://github.com/example/plugin/blob/abc/main.py#L10"
        finding.source_status = "linked"
        report.findings = [finding]
        summary = capabilities.build_reviewer_capabilities(report)

        markdown = capabilities.render_reviewer_capabilities(summary)

        self.assertIn("## Reviewer Capability Summary", markdown)
        self.assertIn("does not change classification", markdown)
        self.assertIn("Can this plugin execute commands or launch processes?", markdown)
        self.assertIn("**DETECTED**", markdown)
        self.assertIn("https://github.com/example/plugin/blob/abc/main.py#L10", markdown)


if __name__ == "__main__":
    unittest.main()
