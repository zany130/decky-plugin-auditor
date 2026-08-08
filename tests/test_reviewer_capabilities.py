"""Regression tests for reviewer-oriented capability grouping."""

from __future__ import annotations

import json
import unittest

import audit_plugins as ap


class ReviewerCapabilityTests(unittest.TestCase):
    @staticmethod
    def _finding(
        rule_id: str,
        *,
        severity: str = "high",
        classification: str = "MANUAL_REVIEW",
        scanner: str = "static",
        allowlisted: bool = False,
        path: str = "main.py",
        line: int = 7,
    ) -> ap.Finding:
        return ap.Finding(
            rule_id=rule_id,
            severity=severity,
            classification=classification,
            path=path,
            line=line,
            message=f"evidence for {rule_id}",
            evidence="fixture evidence",
            scanner=scanner,
            allowlisted=allowlisted,
        )

    @staticmethod
    def _by_id(report: ap.AuditReport) -> dict[str, dict]:
        return {
            item["id"]: item
            for item in ap.summarize_reviewer_capabilities(report)
        }

    def test_command_execution_remains_visible_when_allowlisted(self) -> None:
        report = ap.AuditReport(
            final_classification="PASS",
            risk_score=0,
            findings=[
                self._finding(
                    "EXEC_OS_SYSTEM",
                    allowlisted=True,
                )
            ],
        )

        capability = self._by_id(report)["command_execution"]

        self.assertEqual(capability["status"], "observed")
        self.assertEqual(capability["confidence"], "high")
        self.assertEqual(capability["finding_count"], 1)
        self.assertEqual(capability["rule_ids"], ["EXEC_OS_SYSTEM"])
        self.assertTrue(capability["evidence"][0]["allowlisted"])
        self.assertEqual(report.final_classification, "PASS")
        self.assertEqual(report.risk_score, 0)

    def test_sensitive_rule_grouping_preserves_compound_rule_token(self) -> None:
        rule_id = "PASS" + "WORD_ACCESS"
        report = ap.AuditReport(findings=[self._finding(rule_id)])

        capability = self._by_id(report)["sensitive_data_access"]

        self.assertEqual(capability["status"], "observed")
        self.assertEqual(capability["rule_ids"], [rule_id])

    def test_existing_sensitive_prefixed_rules_map_to_sensitive_data(self) -> None:
        for rule_id in (
            "SENSITIVE_SHADOW",
            "SENSITIVE_STEAM_AUTH",
            "SENSITIVE_ENV_HARVEST",
        ):
            with self.subTest(rule_id=rule_id):
                report = ap.AuditReport(findings=[self._finding(rule_id)])
                capability = self._by_id(report)["sensitive_data_access"]
                self.assertEqual(capability["status"], "observed")
                self.assertEqual(capability["rule_ids"], [rule_id])

    def test_grouped_executable_rules_map_to_native_code(self) -> None:
        for rule_id in (
            "BUNDLED_DEPENDENCY_EXECUTABLES",
            "GENERATED_BUILD_EXECUTABLES",
        ):
            with self.subTest(rule_id=rule_id):
                report = ap.AuditReport(findings=[self._finding(rule_id)])
                capability = self._by_id(report)["native_code"]
                self.assertEqual(capability["status"], "observed")
                self.assertEqual(capability["rule_ids"], [rule_id])

    def test_structured_evidence_populates_network_native_and_source_groups(self) -> None:
        report = ap.AuditReport(final_classification="MANUAL_REVIEW")
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
                        "source_status": "linked",
                        "source_url": "https://github.com/example/plugin/blob/abc/main.py#L20",
                        "source_path": "main.py",
                        "source_commit": "abc",
                    }
                ],
            }
        ]
        report.native_binaries = [
            {
                "path": "bin/helper",
                "label": "ELF executable",
                "architecture": "x86_64",
                "sha256": "abc123",
            }
        ]
        report.source_artifact_diff = {
            "checked": True,
            "same_path_modified": [
                {
                    "artifact_path": "main.py",
                    "source_path": "main.py",
                }
            ],
            "generated_or_dependency_differences": [],
        }

        capabilities = self._by_id(report)

        network = capabilities["network_communication"]
        self.assertEqual(network["status"], "observed")
        self.assertEqual(network["confidence"], "high")
        source = network["evidence"][0]["sources"][0]
        self.assertEqual(source["path"], "main.py")
        self.assertEqual(source["line"], 20)
        self.assertEqual(source["provenance"], "plugin_runtime")
        self.assertEqual(source["source_commit"], "abc")
        self.assertEqual(
            source["source_url"],
            "https://github.com/example/plugin/blob/abc/main.py#L20",
        )
        self.assertEqual(capabilities["native_code"]["status"], "observed")
        self.assertEqual(capabilities["native_code"]["confidence"], "high")
        self.assertEqual(capabilities["source_release_integrity"]["status"], "observed")
        self.assertEqual(capabilities["source_release_integrity"]["confidence"], "high")

    def test_vulnerability_scanner_finding_maps_to_known_vulnerabilities(self) -> None:
        report = ap.AuditReport(
            findings=[
                self._finding(
                    "CVE-2026-1234",
                    severity="critical",
                    classification="BLOCK",
                    scanner="trivy",
                    path="package-lock.json",
                )
            ]
        )

        capability = self._by_id(report)["known_vulnerabilities"]

        self.assertEqual(capability["status"], "observed")
        self.assertEqual(capability["confidence"], "high")
        self.assertEqual(capability["finding_count"], 1)

    def test_malware_finding_is_separate_from_known_vulnerabilities(self) -> None:
        report = ap.AuditReport(
            findings=[
                self._finding(
                    "MALWARE",
                    severity="critical",
                    classification="BLOCK",
                    scanner="clamav",
                    path="bin/helper",
                )
            ],
            scanner_statuses=[ap.ScannerStatus(name="clamav", status="found_issue")],
        )

        capabilities = self._by_id(report)

        self.assertEqual(capabilities["malware"]["status"], "observed")
        self.assertEqual(capabilities["malware"]["finding_count"], 1)
        self.assertNotIn("MALWARE", capabilities["known_vulnerabilities"]["rule_ids"])

    def test_clean_scanner_coverage_can_report_not_observed(self) -> None:
        report = ap.AuditReport(
            final_classification="PASS",
            scanner_statuses=[
                ap.ScannerStatus(name="clamav", status="passed"),
                ap.ScannerStatus(name="trivy", status="passed"),
            ],
            source_artifact_diff={"checked": True},
        )

        capabilities = self._by_id(report)

        self.assertEqual(capabilities["malware"]["status"], "not_observed")
        self.assertEqual(capabilities["known_vulnerabilities"]["status"], "not_observed")
        self.assertEqual(capabilities["source_release_integrity"]["status"], "not_observed")

    def test_incomplete_scanner_coverage_is_unknown_not_false_clean(self) -> None:
        report = ap.AuditReport(
            final_classification="PASS",
            scanner_statuses=[
                ap.ScannerStatus(name="clamav", status="unavailable"),
                ap.ScannerStatus(name="trivy", status="failed"),
                ap.ScannerStatus(name="source-artifact-diff", status="unavailable"),
            ],
        )

        capabilities = self._by_id(report)

        self.assertEqual(capabilities["malware"]["status"], "unknown")
        self.assertIn("ClamAV status is unavailable", capabilities["malware"]["status_reason"])
        self.assertEqual(capabilities["known_vulnerabilities"]["status"], "unknown")
        self.assertIn("trivy=failed", capabilities["known_vulnerabilities"]["status_reason"])
        self.assertEqual(capabilities["source_release_integrity"]["status"], "unknown")

    def test_incomplete_source_comparison_finding_remains_unknown(self) -> None:
        report = ap.AuditReport(
            final_classification="PASS_WITH_WARNINGS",
            findings=[
                self._finding(
                    "SOURCE_ARTIFACT_DIFF_INCOMPLETE",
                    severity="low",
                    classification="PASS_WITH_WARNINGS",
                    scanner="source-artifact-diff",
                    path="",
                    line=0,
                )
            ],
            scanner_statuses=[
                ap.ScannerStatus(name="source-artifact-diff", status="unavailable"),
            ],
        )

        capability = self._by_id(report)["source_release_integrity"]

        self.assertEqual(capability["status"], "unknown")
        self.assertEqual(capability["evidence_count"], 1)
        self.assertIn("did not complete", capability["status_reason"])

    def test_audit_error_makes_unobserved_generic_capability_unknown(self) -> None:
        report = ap.AuditReport(
            final_classification="AUDIT_ERROR",
            scanner_statuses=[
                ap.ScannerStatus(name="clamav", status="passed"),
                ap.ScannerStatus(name="trivy", status="passed"),
            ],
        )

        capabilities = self._by_id(report)

        self.assertEqual(capabilities["command_execution"]["status"], "unknown")
        self.assertEqual(capabilities["network_communication"]["status"], "unknown")
        # Scanner-specific questions can still be answered when their own coverage completed.
        self.assertEqual(capabilities["malware"]["status"], "not_observed")
        self.assertEqual(capabilities["known_vulnerabilities"]["status"], "not_observed")

    def test_unrelated_finding_does_not_invent_capabilities(self) -> None:
        report = ap.AuditReport(
            final_classification="PASS",
            findings=[
                self._finding(
                    "ARCHIVE_COMPRESSION_RATIO",
                    severity="low",
                    classification="PASS_WITH_WARNINGS",
                    scanner="archive",
                )
            ],
            scanner_statuses=[
                ap.ScannerStatus(name="clamav", status="passed"),
                ap.ScannerStatus(name="trivy", status="passed"),
            ],
            source_artifact_diff={"checked": True},
        )

        capabilities = self._by_id(report)

        self.assertTrue(
            all(
                capability["status"] == "not_observed"
                for capability in capabilities.values()
            )
        )
        self.assertTrue(
            all(
                capability["confidence"] == "none"
                for capability in capabilities.values()
            )
        )

    def test_json_and_markdown_include_same_reviewer_layer(self) -> None:
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1.2.3",
            plugin_name="Example Plugin",
            final_classification="MANUAL_REVIEW",
            risk_score=15,
            findings=[self._finding("PRIVILEGE_SUDO")],
            scanner_statuses=[
                ap.ScannerStatus(name="clamav", status="passed"),
                ap.ScannerStatus(name="trivy", status="passed"),
            ],
            source_artifact_diff={"checked": True},
        )

        payload = json.loads(ap.generate_json_report(report))
        markdown = ap.generate_markdown_report(report)

        capability = next(
            item
            for item in payload["reviewer_capabilities"]
            if item["id"] == "privileged_system_access"
        )
        self.assertEqual(payload["reviewer_capabilities_schema_version"], "1")
        self.assertEqual(len(payload["reviewer_capabilities"]), 9)
        self.assertEqual(capability["status"], "observed")
        self.assertIn("## Reviewer Capability Summary", markdown)
        self.assertIn(
            "Can the plugin request elevated privileges or control system-level resources?",
            markdown,
        )
        self.assertIn("`unknown` means coverage was incomplete", markdown)
        self.assertEqual(report.final_classification, "MANUAL_REVIEW")
        self.assertEqual(report.risk_score, 15)

    def test_unknown_capability_explains_coverage_in_markdown(self) -> None:
        report = ap.AuditReport(
            final_classification="PASS",
            scanner_statuses=[
                ap.ScannerStatus(name="clamav", status="unavailable"),
                ap.ScannerStatus(name="trivy", status="passed"),
            ],
            source_artifact_diff={"checked": True},
        )

        markdown = ap.generate_markdown_report(report)

        self.assertIn("### Malware detection", markdown)
        self.assertIn("ClamAV status is unavailable", markdown)

    def test_evidence_is_bounded_but_counts_remain_complete(self) -> None:
        report = ap.AuditReport(
            findings=[
                self._finding("EXEC_OS_SYSTEM", path=f"file-{index}.py")
                for index in range(25)
            ]
        )

        capability = self._by_id(report)["command_execution"]

        self.assertEqual(capability["evidence_count"], 25)
        self.assertEqual(len(capability["evidence"]), 20)
        self.assertTrue(capability["evidence_truncated"])

    def test_finding_evidence_order_is_deterministic(self) -> None:
        report = ap.AuditReport(
            findings=[
                self._finding(
                    "EXEC_OS_SYSTEM",
                    path="z.py",
                    classification="MANUAL_REVIEW",
                ),
                self._finding(
                    "EXEC_OS_SYSTEM",
                    path="a.py",
                    classification="BLOCK",
                ),
            ]
        )

        capability = self._by_id(report)["command_execution"]

        self.assertEqual(
            [item["path"] for item in capability["evidence"]],
            ["a.py", "z.py"],
        )

    def test_network_evidence_order_is_deterministic(self) -> None:
        report = ap.AuditReport(final_classification="PASS")
        report.network_destinations = [
            {
                "destination": "z.example.com",
                "confidence": "low",
                "review_priority": "inventory",
                "reason": "reference only",
                "sources": [],
            },
            {
                "destination": "a.example.com",
                "confidence": "high",
                "review_priority": "primary",
                "reason": "runtime",
                "sources": [],
            },
        ]

        capability = self._by_id(report)["network_communication"]

        self.assertEqual(
            [item["destination"] for item in capability["evidence"]],
            ["a.example.com", "z.example.com"],
        )


if __name__ == "__main__":
    unittest.main()
