"""Regression tests for reviewer capability release comparisons."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import audit_plugins as ap


CAPABILITY_IDS = (
    "command_execution",
    "privileged_system_access",
    "persistence",
    "network_communication",
    "sensitive_data_access",
    "native_code",
    "source_release_integrity",
    "malware",
    "known_vulnerabilities",
)


class ReviewerCapabilityComparisonTests(unittest.TestCase):
    SHA_OLD = "0123456789abcdef0123456789abcdef01234567"
    SHA_NEW = "89abcdef0123456789abcdef0123456789abcdef"

    @staticmethod
    def _capability(
        capability_id: str,
        *,
        status: str = "not_observed",
        evidence: list[dict] | None = None,
        rule_ids: list[str] | None = None,
    ) -> dict:
        evidence = list(evidence or [])
        return {
            "id": capability_id,
            "title": capability_id.replace("_", " ").title(),
            "question": f"What about {capability_id}?",
            "status": status,
            "status_reason": "fixture",
            "confidence": "high" if status == "observed" else "none",
            "finding_count": sum(
                1 for item in evidence if item.get("kind") == "finding"
            ),
            "evidence_count": len(evidence),
            "rule_ids": list(rule_ids or []),
            "evidence": evidence,
            "evidence_truncated": False,
        }

    def _report(
        self,
        *,
        release: str,
        artifact: str,
        commit: str,
        overrides: dict[str, dict] | None = None,
        schema: str = "1",
    ) -> ap.AuditReport:
        overrides = overrides or {}
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release=release,
            artifact_sha256=artifact,
            final_classification="MANUAL_REVIEW",
            risk_score=42,
        )
        report.source_commit = commit
        report.reviewer_capabilities_schema_version = schema
        report.reviewer_capabilities = [
            overrides.get(capability_id)
            or self._capability(capability_id)
            for capability_id in CAPABILITY_IDS
        ]
        return report

    def test_not_observed_to_observed_is_newly_observed_with_immutable_evidence(self) -> None:
        source_url = (
            f"https://github.com/example/plugin/blob/{self.SHA_NEW}/main.py#L12"
        )
        current_command = self._capability(
            "command_execution",
            status="observed",
            rule_ids=["EXEC_SUBPROCESS_POPEN"],
            evidence=[
                {
                    "kind": "finding",
                    "rule_id": "EXEC_SUBPROCESS_POPEN",
                    "path": "main.py",
                    "line": 12,
                    "context": "command or subprocess execution",
                    "source_status": "linked",
                    "source_line_exact": True,
                    "immutable_source_url": source_url,
                }
            ],
        )
        baseline = self._report(
            release="v1.0.0",
            artifact="a" * 64,
            commit=self.SHA_OLD,
        )
        current = self._report(
            release="v2.0.0",
            artifact="b" * 64,
            commit=self.SHA_NEW,
            overrides={"command_execution": current_command},
        )

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        command = next(
            item
            for item in comparison["capabilities"]
            if item["id"] == "command_execution"
        )
        markdown = ap.render_reviewer_capability_comparison(comparison)

        self.assertEqual(comparison["status"], "compared")
        self.assertEqual(comparison["changed_count"], 1)
        self.assertEqual(command["status_change"], "newly_observed")
        self.assertTrue(command["reviewer_attention"])
        self.assertEqual(
            command["details"]["added_rule_ids"], ["EXEC_SUBPROCESS_POPEN"]
        )
        self.assertEqual(
            command["current_change_evidence"][0]["immutable_source_url"],
            source_url,
        )
        self.assertIn(source_url, markdown)
        self.assertIn("not_observed", markdown)
        self.assertIn("observed", markdown)

    def test_unknown_to_observed_is_not_mislabeled_as_new_behavior(self) -> None:
        baseline = self._report(
            release="v1",
            artifact="a" * 64,
            commit=self.SHA_OLD,
            overrides={
                "malware": self._capability("malware", status="unknown")
            },
        )
        current = self._report(
            release="v2",
            artifact="b" * 64,
            commit=self.SHA_NEW,
            overrides={
                "malware": self._capability(
                    "malware",
                    status="observed",
                    rule_ids=["MALWARE"],
                    evidence=[
                        {
                            "kind": "finding",
                            "rule_id": "MALWARE",
                            "path": "payload.bin",
                            "line": 0,
                            "context": "malware scanner finding",
                        }
                    ],
                )
            },
        )

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        malware = next(
            item for item in comparison["capabilities"] if item["id"] == "malware"
        )

        self.assertEqual(malware["status_change"], "now_observed_after_unknown")
        self.assertNotEqual(malware["status_change"], "newly_observed")

    def test_network_destination_delta_is_semantic_and_deterministic(self) -> None:
        baseline_network = self._capability(
            "network_communication",
            status="observed",
            evidence=[
                {
                    "kind": "network_destination",
                    "destination": "old.example.com",
                    "confidence": "high",
                    "reason": "runtime",
                    "sources": [],
                },
                {
                    "kind": "network_destination",
                    "destination": "shared.example.com",
                    "confidence": "high",
                    "reason": "runtime",
                    "sources": [],
                },
            ],
        )
        new_url = (
            f"https://github.com/example/plugin/blob/{self.SHA_NEW}/network.py#L20"
        )
        current_network = self._capability(
            "network_communication",
            status="observed",
            evidence=[
                {
                    "kind": "network_destination",
                    "destination": "new.example.com",
                    "confidence": "high",
                    "reason": "runtime",
                    "sources": [
                        {
                            "path": "network.py",
                            "line": 20,
                            "source_status": "linked",
                            "source_line_exact": True,
                            "immutable_source_url": new_url,
                        }
                    ],
                },
                {
                    "kind": "network_destination",
                    "destination": "shared.example.com",
                    "confidence": "high",
                    "reason": "runtime",
                    "sources": [],
                },
            ],
        )
        baseline = self._report(
            release="v1",
            artifact="a" * 64,
            commit=self.SHA_OLD,
            overrides={"network_communication": baseline_network},
        )
        current = self._report(
            release="v2",
            artifact="b" * 64,
            commit=self.SHA_NEW,
            overrides={"network_communication": current_network},
        )

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        network = next(
            item
            for item in comparison["capabilities"]
            if item["id"] == "network_communication"
        )
        markdown = ap.render_reviewer_capability_comparison(comparison)

        self.assertEqual(network["status_change"], "unchanged")
        self.assertEqual(
            network["evidence_changes"], ["network_destinations_changed"]
        )
        self.assertEqual(
            network["details"]["added_destinations"], ["new.example.com"]
        )
        self.assertEqual(
            network["details"]["removed_destinations"], ["old.example.com"]
        )
        self.assertEqual(
            network["current_change_evidence"][0]["destination"],
            "new.example.com",
        )
        self.assertIn(new_url, markdown)

    def test_old_baseline_without_capabilities_degrades_gracefully(self) -> None:
        current = self._report(
            release="v2",
            artifact="b" * 64,
            commit=self.SHA_NEW,
        )
        baseline = {
            "repository": "https://github.com/example/plugin",
            "release": "v1",
            "artifact_sha256": "a" * 64,
        }

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        markdown = ap.render_reviewer_capability_comparison(comparison)

        self.assertEqual(
            comparison["status"], "baseline_capabilities_unavailable"
        )
        self.assertEqual(comparison["capabilities"], [])
        self.assertIn("Comparison unavailable", markdown)
        self.assertIn("No previous-release behavior was inferred", markdown)

    def test_schema_mismatch_is_not_compared(self) -> None:
        baseline = self._report(
            release="v1",
            artifact="a" * 64,
            commit=self.SHA_OLD,
            schema="2",
        )
        current = self._report(
            release="v2",
            artifact="b" * 64,
            commit=self.SHA_NEW,
        )

        comparison = ap.compare_reviewer_capabilities(current, baseline)

        self.assertEqual(comparison["status"], "baseline_schema_unsupported")
        self.assertEqual(comparison["changed_count"], 0)

    def test_same_artifact_is_explicit_even_when_capabilities_match(self) -> None:
        baseline = self._report(
            release="v1",
            artifact="a" * 64,
            commit=self.SHA_OLD,
        )
        current = self._report(
            release="v1",
            artifact="a" * 64,
            commit=self.SHA_OLD,
        )

        comparison = ap.compare_reviewer_capabilities(current, baseline)

        self.assertEqual(comparison["status"], "compared")
        self.assertTrue(comparison["same_artifact"])
        self.assertEqual(comparison["changed_count"], 0)

    def test_baseline_loader_accepts_aggregate_and_rejects_ambiguous_duplicates(self) -> None:
        payload = {
            "repository": "https://github.com/example/plugin",
            "release": "v1",
            "artifact_sha256": "a" * 64,
            "reviewer_capabilities_schema_version": "1",
            "reviewer_capabilities": [
                self._capability(capability_id)
                for capability_id in CAPABILITY_IDS
            ],
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "baseline.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"reports": [payload]}, handle)
            indexed = ap.load_baseline_report(path)
            self.assertIn("github.com/example/plugin", indexed)

            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"reports": [payload, payload]}, handle)
            with self.assertRaises(ValueError):
                ap.load_baseline_report(path)

    def test_baseline_semantic_values_are_redacted_in_comparison_json(self) -> None:
        secret = "ghp_" + ("A" * 36)
        baseline_network = self._capability(
            "network_communication",
            status="observed",
            evidence=[
                {
                    "kind": "network_destination",
                    "destination": f"api.example.com/{secret}",
                    "confidence": "low",
                    "reason": "legacy fixture",
                    "sources": [],
                }
            ],
        )
        current_network = self._capability(
            "network_communication",
            status="observed",
            evidence=[],
        )
        baseline = self._report(
            release="v1",
            artifact="a" * 64,
            commit=self.SHA_OLD,
            overrides={"network_communication": baseline_network},
        )
        current = self._report(
            release="v2",
            artifact="b" * 64,
            commit=self.SHA_NEW,
            overrides={"network_communication": current_network},
        )

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        payload = json.dumps(comparison)
        markdown = ap.render_reviewer_capability_comparison(comparison)

        self.assertNotIn(secret, payload)
        self.assertNotIn(secret, markdown)
        self.assertIn("[REDACTED]", payload)

    def test_no_baseline_keeps_legacy_json_shape_unchanged(self) -> None:
        report = ap.AuditReport(final_classification="PASS")
        payload = json.loads(ap.generate_json_report(report))

        self.assertNotIn("reviewer_capability_comparison", payload)
        self.assertNotIn(
            "reviewer_capability_comparison_schema_version", payload
        )


if __name__ == "__main__":
    unittest.main()
