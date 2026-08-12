"""Compatibility regressions for cached reports with legacy network inventories."""

from __future__ import annotations

import unittest

import reviewer_capability_comparison as comparison


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


class ReviewerCapabilityLegacyNetworkCompatibilityTests(unittest.TestCase):
    @staticmethod
    def _capabilities() -> list[dict[str, object]]:
        return [
            {
                "id": capability_id,
                "title": capability_id.replace("_", " ").title(),
                "question": f"What about {capability_id}?",
                "status": (
                    "observed"
                    if capability_id == "network_communication"
                    else "not_observed"
                ),
                "rule_ids": [],
                "evidence": [],
            }
            for capability_id in CAPABILITY_IDS
        ]

    @classmethod
    def _report(cls, *, destinations: list[str]) -> dict[str, object]:
        return {
            "repository": "https://github.com/example/plugin",
            "release": "v1.0.0",
            "artifact_sha256": "a" * 64,
            "source_commit": "1" * 40,
            "final_classification": "PASS",
            "risk_score": 0,
            "reviewer_capabilities_schema_version": "1",
            "reviewer_capabilities": cls._capabilities(),
            "network_destinations": [
                {"destination": destination} for destination in destinations
            ],
        }

    def test_empty_structured_inventory_falls_back_to_complete_legacy_domains(self) -> None:
        domains = [f"host-{index}.example.com" for index in range(35)]
        report = self._report(destinations=[])
        report["extracted_domains"] = domains
        network_capability = next(
            item
            for item in report["reviewer_capabilities"]
            if item["id"] == "network_communication"
        )
        # Reviewer evidence is intentionally capped; the comparator must not use
        # this bounded display projection when the full legacy inventory exists.
        network_capability["evidence"] = [
            {"kind": "network_destination", "destination": value}
            for value in domains[:20]
        ]

        self.assertEqual(
            comparison._network_destinations(report, network_capability),
            set(domains),
        )

    def test_semantically_empty_structured_inventory_falls_back_to_legacy(self) -> None:
        report = self._report(destinations=[])
        report["network_destinations"] = [
            {},
            {"destination": ""},
            {"destination": "   "},
            "not-an-object",
        ]
        report["extracted_domains"] = ["  legacy.example.com  ", "", "   "]
        network_capability = next(
            item
            for item in report["reviewer_capabilities"]
            if item["id"] == "network_communication"
        )

        self.assertEqual(
            comparison._network_destinations(report, network_capability),
            {"legacy.example.com"},
        )

    def test_nonempty_structured_inventory_remains_authoritative(self) -> None:
        report = self._report(destinations=[])
        report["network_destinations"] = [
            {"destination": "  structured.example.com  "},
        ]
        report["extracted_domains"] = ["legacy.example.com"]
        network_capability = next(
            item
            for item in report["reviewer_capabilities"]
            if item["id"] == "network_communication"
        )

        self.assertEqual(
            comparison._network_destinations(report, network_capability),
            {"structured.example.com"},
        )

    def test_same_artifact_cached_shape_does_not_create_false_network_removals(self) -> None:
        domains = [f"host-{index}.example.com" for index in range(35)]
        baseline = self._report(destinations=domains)
        current = self._report(destinations=[])
        current["extracted_domains"] = domains

        result = comparison.compare_reviewer_capabilities(current, baseline)
        network = next(
            item
            for item in result["capabilities"]
            if item["id"] == "network_communication"
        )

        self.assertEqual(result["status"], "compared")
        self.assertTrue(result["same_artifact"])
        self.assertEqual(result["changed_count"], 0)
        self.assertEqual(result["attention_count"], 0)
        self.assertFalse(network["changed"])
        self.assertEqual(network["evidence_changes"], [])
        self.assertNotIn("removed_destinations", network["details"])


if __name__ == "__main__":
    unittest.main()
