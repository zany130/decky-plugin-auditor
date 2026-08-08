"""Integration checks for opt-in capability comparison report surfaces."""

from __future__ import annotations

import json
import unittest

import audit_plugins as ap


class ReviewerCapabilityComparisonSerializationTests(unittest.TestCase):
    def test_comparison_runtime_data_reaches_json_and_markdown(self) -> None:
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v2",
            artifact_sha256="b" * 64,
            final_classification="PASS",
        )
        report.reviewer_capability_comparison = {
            "status": "baseline_not_found",
            "status_reason": "No baseline report matched this repository.",
            "baseline": {},
            "current": {},
            "same_artifact": False,
            "changed_count": 0,
            "attention_count": 0,
            "capabilities": [],
        }

        payload = json.loads(ap.generate_json_report(report))
        markdown = ap.generate_markdown_report(report)

        self.assertEqual(
            payload["reviewer_capability_comparison_schema_version"], "1"
        )
        self.assertEqual(
            payload["reviewer_capability_comparison"]["status"],
            "baseline_not_found",
        )
        self.assertIn("## Capability Changes Against Baseline", markdown)
        self.assertIn("Comparison unavailable", markdown)
        self.assertEqual(markdown.count("## Reviewer Capability Summary"), 1)


if __name__ == "__main__":
    unittest.main()
