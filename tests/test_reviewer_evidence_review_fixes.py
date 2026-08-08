"""Regression coverage for PR review hardening of reviewer provenance."""

from __future__ import annotations

import json
import unittest

import audit_plugins as ap
import reviewer_evidence_provenance as provenance


class ReviewerEvidenceReviewFixTests(unittest.TestCase):
    def test_markdown_text_escapes_emphasis_and_table_metacharacters(self) -> None:
        rendered = provenance._md("reason_with*format|break~~")

        self.assertEqual(rendered, r"reason\_with\*format\|break\~\~")

    def test_finding_provenance_redacts_source_path_and_url(self) -> None:
        secret = "ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        commit = "1" * 40
        finding = ap.Finding(
            rule_id="EXEC_SUBPROCESS_POPEN",
            severity="high",
            classification="MANUAL_REVIEW",
            path="main.py",
            line=7,
            message="fixture",
            evidence="fixture",
            scanner="decky-static-rules",
        )
        finding.source_status = "linked"
        finding.source_path = f"src/{secret}/main.py"
        finding.source_url = (
            f"https://github.com/example/plugin/blob/{commit}/src/{secret}/main.py#L7"
        )
        finding.source_commit = commit
        finding.source_line_exact = True

        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1.0.0",
            findings=[finding],
            source_artifact_diff={"checked": True},
        )
        report.source_commit = commit

        capability = next(
            item
            for item in ap.summarize_reviewer_capabilities(report)
            if item["id"] == "command_execution"
        )
        evidence = capability["evidence"][0]
        serialized = json.dumps(capability)
        markdown = ap.render_reviewer_capabilities([capability], report)

        self.assertNotIn(secret, serialized)
        self.assertNotIn(secret, markdown)
        self.assertIn("[REDACTED]", evidence["source_path"])
        self.assertIn("[REDACTED]", evidence["source_url"])
        self.assertNotIn("immutable_source_url", evidence)

    def test_network_provenance_redacts_source_path_and_url(self) -> None:
        secret = "ghp_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"
        commit = "2" * 40
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v1.0.0",
            source_artifact_diff={"checked": True},
        )
        report.source_commit = commit
        report.network_destinations = [
            {
                "destination": "api.example.com",
                "confidence": "high",
                "review_priority": "primary",
                "reason": "runtime destination",
                "sources": [
                    {
                        "path": "main.py",
                        "line": 10,
                        "provenance": "plugin_runtime",
                        "confidence": "high",
                        "source_status": "linked",
                        "source_path": f"src/{secret}/main.py",
                        "source_url": (
                            f"https://github.com/example/plugin/blob/{commit}/src/{secret}/main.py#L10"
                        ),
                        "source_commit": commit,
                        "source_line_exact": True,
                    }
                ],
            }
        ]

        capability = next(
            item
            for item in ap.summarize_reviewer_capabilities(report)
            if item["id"] == "network_communication"
        )
        source = capability["evidence"][0]["sources"][0]
        serialized = json.dumps(capability)
        markdown = ap.render_reviewer_capabilities([capability], report)

        self.assertNotIn(secret, serialized)
        self.assertNotIn(secret, markdown)
        self.assertIn("[REDACTED]", source["source_path"])
        self.assertIn("[REDACTED]", source["source_url"])
        self.assertNotIn("immutable_source_url", source)


if __name__ == "__main__":
    unittest.main()
