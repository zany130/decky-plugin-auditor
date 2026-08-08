"""Regression tests for reviewer evidence provenance and rendering safety."""

from __future__ import annotations

import json
import unittest

import audit_plugins as ap


class ReviewerEvidenceProvenanceTests(unittest.TestCase):
    SHA = "0123456789abcdef0123456789abcdef01234567"

    @staticmethod
    def _finding(
        rule_id: str = "PRIVILEGE_SUDO",
        *,
        path: str = "main.py",
        line: int = 7,
        scanner: str = "decky-static-rules",
        allowlisted: bool = False,
    ) -> ap.Finding:
        return ap.Finding(
            rule_id=rule_id,
            severity="high",
            classification="MANUAL_REVIEW",
            path=path,
            line=line,
            message="fixture finding",
            evidence="fixture evidence",
            scanner=scanner,
            allowlisted=allowlisted,
        )

    def _linked_report(self, finding: ap.Finding) -> ap.AuditReport:
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1.2.3",
            artifact_sha256="a" * 64,
            final_classification="MANUAL_REVIEW",
            findings=[finding],
            source_artifact_diff={"checked": True},
        )
        report.source_commit = self.SHA
        finding.source_status = "linked"
        finding.source_path = finding.path
        finding.source_commit = self.SHA
        finding.source_url = (
            f"https://github.com/example/plugin/blob/{self.SHA}/{finding.path}"
            f"#L{finding.line}"
        )
        return report

    @staticmethod
    def _capability(report: ap.AuditReport, capability_id: str) -> dict:
        return next(
            item
            for item in ap.summarize_reviewer_capabilities(report)
            if item["id"] == capability_id
        )

    def test_exact_finding_gets_commit_pinned_line_link_and_audit_identity(self) -> None:
        finding = self._finding()
        report = self._linked_report(finding)

        capability = self._capability(report, "privileged_system_access")
        evidence = capability["evidence"][0]
        markdown = ap.render_reviewer_capabilities(
            ap.summarize_reviewer_capabilities(report), report
        )

        expected = f"https://github.com/example/plugin/blob/{self.SHA}/main.py#L7"
        self.assertEqual(evidence["immutable_source_url"], expected)
        self.assertTrue(evidence["source_line_exact"])
        self.assertIn(f"[immutable upstream source]({expected})", markdown)
        self.assertIn(
            f"[{self.SHA[:12]}](https://github.com/example/plugin/commit/{self.SHA})",
            markdown,
        )
        self.assertIn("Exact release/source comparison: `completed`", markdown)
        self.assertIn("Artifact SHA-256: `" + ("a" * 64) + "`", markdown)

    def test_modified_artifact_file_links_to_commit_file_without_line_claim(self) -> None:
        finding = self._finding()
        report = self._linked_report(finding)
        report.source_artifact_diff = {
            "checked": True,
            "same_path_modified": [
                {"artifact_path": "main.py", "source_path": "main.py"}
            ],
        }

        capability = self._capability(report, "privileged_system_access")
        evidence = capability["evidence"][0]
        markdown = ap.render_reviewer_capabilities(
            ap.summarize_reviewer_capabilities(report), report
        )

        expected_file = f"https://github.com/example/plugin/blob/{self.SHA}/main.py"
        self.assertEqual(evidence["immutable_source_url"], expected_file)
        self.assertFalse(evidence["source_line_exact"])
        self.assertIn("release contents differ from tagged source", evidence["source_note"])
        self.assertIn(f"[tagged source file]({expected_file})", markdown)
        self.assertNotIn(expected_file + "#L7", markdown)

    def test_legacy_short_commit_is_preserved_but_never_rendered_as_immutable(self) -> None:
        finding = self._finding()
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1",
            final_classification="MANUAL_REVIEW",
            findings=[finding],
            source_artifact_diff={"checked": True},
        )
        finding.source_status = "linked"
        finding.source_path = "main.py"
        finding.source_commit = "abc"
        finding.source_url = "https://github.com/example/plugin/blob/abc/main.py#L7"

        evidence = self._capability(report, "privileged_system_access")["evidence"][0]
        markdown = ap.render_reviewer_capabilities(
            ap.summarize_reviewer_capabilities(report), report
        )

        self.assertEqual(evidence["source_commit"], "abc")
        self.assertEqual(
            evidence["source_url"],
            "https://github.com/example/plugin/blob/abc/main.py#L7",
        )
        self.assertNotIn("immutable_source_url", evidence)
        self.assertNotIn("blob/abc", markdown)
        self.assertIn("immutable upstream source link unavailable", markdown)

    def test_network_summary_renders_immutable_source_references(self) -> None:
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1",
            final_classification="PASS",
        )
        report.source_commit = self.SHA
        report.network_destinations = [
            {
                "destination": "api.example.com",
                "confidence": "high",
                "review_priority": "primary",
                "reason": "plugin-owned runtime reference",
                "sources": [
                    {
                        "path": "main.py",
                        "line": 20,
                        "provenance": "plugin_runtime",
                        "confidence": "high",
                        "source_status": "linked",
                        "source_path": "main.py",
                        "source_commit": self.SHA,
                        "source_url": (
                            f"https://github.com/example/plugin/blob/{self.SHA}/main.py#L20"
                        ),
                        "source_line_exact": True,
                    }
                ],
            }
        ]

        capability = self._capability(report, "network_communication")
        source = capability["evidence"][0]["sources"][0]
        markdown = ap.render_reviewer_capabilities(
            ap.summarize_reviewer_capabilities(report), report
        )

        self.assertEqual(
            source["immutable_source_url"],
            f"https://github.com/example/plugin/blob/{self.SHA}/main.py#L20",
        )
        self.assertIn("immutable upstream source", markdown)
        self.assertIn("api.example.com", markdown)

    def test_source_diff_samples_distinguish_file_link_from_release_only(self) -> None:
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1",
            final_classification="MANUAL_REVIEW",
            source_artifact_diff={
                "checked": True,
                "same_path_modified": [
                    {"artifact_path": "main.py", "source_path": "main.py"}
                ],
                "zip_only_scripts": ["dist/generated.sh"],
            },
        )
        report.source_commit = self.SHA

        capability = self._capability(report, "source_release_integrity")
        evidence_by_category = {
            item["category"]: item
            for item in capability["evidence"]
            if item["kind"] == "source_artifact_diff"
        }
        modified = evidence_by_category["same_path_modified"]["samples"][0]
        release_only = evidence_by_category["zip_only_scripts"]["samples"][0]
        markdown = ap.render_reviewer_capabilities(
            ap.summarize_reviewer_capabilities(report), report
        )

        self.assertEqual(modified["source_status"], "file-only")
        self.assertEqual(
            modified["immutable_source_url"],
            f"https://github.com/example/plugin/blob/{self.SHA}/main.py",
        )
        self.assertEqual(release_only["source_status"], "release-only")
        self.assertNotIn("immutable_source_url", release_only)
        self.assertIn("release-only; no upstream source file", markdown)

    def test_duplicate_findings_are_collapsed_before_summary_cap(self) -> None:
        report = ap.AuditReport(
            findings=[self._finding(path="same.py", line=10) for _ in range(25)]
        )

        capability = self._capability(report, "privileged_system_access")

        self.assertEqual(capability["finding_count"], 25)
        self.assertEqual(capability["evidence_count"], 25)
        self.assertEqual(capability["distinct_evidence_count"], 1)
        self.assertEqual(capability["evidence_collapsed"], 24)
        self.assertEqual(len(capability["evidence"]), 1)
        self.assertFalse(capability["evidence_truncated"])

    def test_structured_evidence_is_reserved_before_raw_finding_cap(self) -> None:
        report = ap.AuditReport(
            findings=[
                self._finding(
                    "NETWORK_HTTP_REQUEST",
                    path=f"file-{index}.py",
                    line=index + 1,
                )
                for index in range(25)
            ]
        )
        report.network_destinations = [
            {
                "destination": "api.example.com",
                "confidence": "high",
                "review_priority": "primary",
                "reason": "runtime",
                "sources": [],
            }
        ]

        capability = self._capability(report, "network_communication")

        self.assertEqual(capability["evidence"][0]["kind"], "network_destination")
        self.assertEqual(len(capability["evidence"]), 20)
        self.assertEqual(capability["distinct_evidence_count"], 26)
        self.assertTrue(capability["evidence_truncated"])

    def test_reviewer_surfaces_redact_secret_shaped_text(self) -> None:
        github_token = "ghp_" + ("A" * 36)
        bearer = "Bearer " + ("B" * 32)
        finding = self._finding(path=f"src/{github_token}/main.py")
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1",
            final_classification="MANUAL_REVIEW",
            findings=[finding],
        )
        report.network_destinations = [
            {
                "destination": "api.example.com",
                "confidence": "low",
                "review_priority": "inventory",
                "reason": f"header observed: {bearer}",
                "sources": [],
            }
        ]

        capabilities = ap.summarize_reviewer_capabilities(report)
        payload = json.dumps(capabilities)
        markdown = ap.render_reviewer_capabilities(capabilities, report)

        self.assertNotIn(github_token, payload)
        self.assertNotIn(github_token, markdown)
        self.assertNotIn(bearer, payload)
        self.assertNotIn(bearer, markdown)
        self.assertIn("[REDACTED]", payload)
        self.assertIn("[REDACTED]", markdown)

    def test_allowlisted_finding_says_capability_is_still_present(self) -> None:
        report = ap.AuditReport(
            final_classification="PASS",
            findings=[self._finding(allowlisted=True)],
        )

        markdown = ap.render_reviewer_capabilities(
            ap.summarize_reviewer_capabilities(report), report
        )

        self.assertIn("allowlisted for enforcement; capability still present", markdown)


if __name__ == "__main__":
    unittest.main()
