"""Full-inventory regression tests for capability release comparison."""

from __future__ import annotations

import unittest
from unittest.mock import patch

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


def capability(
    capability_id: str,
    *,
    status: str = "not_observed",
    evidence: list[dict] | None = None,
) -> dict:
    evidence = list(evidence or [])
    return {
        "id": capability_id,
        "title": capability_id.replace("_", " ").title(),
        "question": capability_id,
        "status": status,
        "status_reason": "fixture",
        "confidence": "high" if status == "observed" else "none",
        "finding_count": 0,
        "evidence_count": len(evidence),
        "rule_ids": [],
        "evidence": evidence,
        "evidence_truncated": False,
    }


def capabilities(overrides: dict[str, dict] | None = None) -> list[dict]:
    overrides = overrides or {}
    return [
        overrides.get(capability_id) or capability(capability_id)
        for capability_id in CAPABILITY_IDS
    ]


class ReviewerCapabilityFullProfileTests(unittest.TestCase):
    SHA = "0123456789abcdef0123456789abcdef01234567"

    def _baseline(self, *, overrides: dict[str, dict] | None = None) -> dict:
        return {
            "repository": "https://github.com/example/plugin",
            "release": "v1",
            "artifact_sha256": "a" * 64,
            "source_commit": self.SHA,
            "reviewer_capabilities_schema_version": "1",
            "reviewer_capabilities": capabilities(overrides),
            "network_destinations": [],
            "native_binaries": [],
            "source_artifact_diff": {"checked": True},
        }

    def _current(self, *, overrides: dict[str, dict] | None = None) -> ap.AuditReport:
        report = ap.AuditReport(
            repository="https://github.com/example/plugin",
            release="v2",
            artifact_sha256="b" * 64,
            final_classification="PASS",
        )
        report.source_commit = self.SHA
        report.reviewer_capabilities_schema_version = "1"
        report.reviewer_capabilities = capabilities(overrides)
        report.network_destinations = []
        report.native_binaries = []
        report.source_artifact_diff = {"checked": True}
        return report

    def test_network_delta_uses_full_inventory_beyond_summary_cap(self) -> None:
        old_destinations = [
            {"destination": f"api-{index:02d}.example.com"}
            for index in range(25)
        ]
        displayed = [
            {
                "kind": "network_destination",
                "destination": item["destination"],
                "confidence": "high",
                "reason": "fixture",
                "sources": [],
            }
            for item in old_destinations[:20]
        ]
        baseline = self._baseline(
            overrides={
                "network_communication": capability(
                    "network_communication",
                    status="observed",
                    evidence=displayed,
                )
            }
        )
        baseline["network_destinations"] = old_destinations

        current = self._current(
            overrides={
                "network_communication": capability(
                    "network_communication",
                    status="observed",
                    evidence=displayed,
                )
            }
        )
        current.network_destinations = old_destinations + [
            {
                "destination": "z-new.example.com",
                "confidence": "high",
                "review_priority": "primary",
                "reason": "new runtime destination",
                "sources": [
                    {
                        "path": "network.py",
                        "line": 50,
                        "provenance": "plugin_runtime",
                        "confidence": "high",
                        "source_status": "linked",
                        "source_path": "network.py",
                        "source_commit": self.SHA,
                        "source_line_exact": True,
                    }
                ],
            }
        ]

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        network = next(
            item
            for item in comparison["capabilities"]
            if item["id"] == "network_communication"
        )

        self.assertEqual(
            network["details"]["added_destinations"],
            ["z-new.example.com"],
        )
        self.assertEqual(
            network["current_change_evidence"][0]["destination"],
            "z-new.example.com",
        )
        self.assertIn(
            f"/blob/{self.SHA}/network.py#L50",
            network["current_change_evidence"][0]["sources"][0][
                "immutable_source_url"
            ],
        )

    def test_native_delta_uses_full_inventory_beyond_summary_cap(self) -> None:
        old_binaries = [
            {
                "path": f"bin/helper-{index:02d}",
                "sha256": f"{index:064x}",
            }
            for index in range(25)
        ]
        displayed = [
            {
                "kind": "native_binary",
                "path": item["path"],
                "sha256": item["sha256"],
                "label": "ELF",
                "architecture": "x86_64",
            }
            for item in old_binaries[:20]
        ]
        baseline = self._baseline(
            overrides={
                "native_code": capability(
                    "native_code", status="observed", evidence=displayed
                )
            }
        )
        baseline["native_binaries"] = old_binaries

        current = self._current(
            overrides={
                "native_code": capability(
                    "native_code", status="observed", evidence=displayed
                )
            }
        )
        new_binary = {
            "path": "bin/z-new-helper",
            "sha256": "f" * 64,
            "label": "ELF",
            "architecture": "x86_64",
        }
        current.native_binaries = old_binaries + [new_binary]

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        native = next(
            item
            for item in comparison["capabilities"]
            if item["id"] == "native_code"
        )

        expected = f"bin/z-new-helper @ sha256:{'f' * 64}"
        self.assertEqual(native["details"]["added_native_binaries"], [expected])
        self.assertEqual(
            native["current_change_evidence"][0]["path"],
            "bin/z-new-helper",
        )

    def test_source_difference_count_change_is_detected(self) -> None:
        source_capability = capability(
            "source_release_integrity",
            status="observed",
            evidence=[
                {
                    "kind": "source_artifact_diff",
                    "category": "same_path_modified",
                    "count": 1,
                    "sample_paths": ["main.py"],
                }
            ],
        )
        baseline = self._baseline(
            overrides={"source_release_integrity": source_capability}
        )
        baseline["source_artifact_diff"] = {
            "checked": True,
            "same_path_modified": [
                {"artifact_path": "main.py", "source_path": "main.py"}
            ],
        }

        current = self._current(
            overrides={"source_release_integrity": source_capability}
        )
        current.source_artifact_diff = {
            "checked": True,
            "same_path_modified": [
                {"artifact_path": "main.py", "source_path": "main.py"},
                {"artifact_path": "extra.py", "source_path": "extra.py"},
            ],
        }

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        integrity = next(
            item
            for item in comparison["capabilities"]
            if item["id"] == "source_release_integrity"
        )

        self.assertIn(
            "source_difference_profile_changed",
            integrity["evidence_changes"],
        )
        self.assertEqual(
            integrity["details"]["changed_source_difference_counts"],
            ["same_path_modified: 1 -> 2"],
        )

    def test_same_artifact_delta_warns_against_release_causality(self) -> None:
        baseline = self._baseline()
        baseline["artifact_sha256"] = "a" * 64
        current = self._current(
            overrides={
                "command_execution": capability(
                    "command_execution",
                    status="observed",
                    evidence=[
                        {
                            "kind": "finding",
                            "rule_id": "EXEC_SUBPROCESS_POPEN",
                            "path": "main.py",
                            "line": 1,
                            "context": "command execution",
                        }
                    ],
                )
            }
        )
        current.artifact_sha256 = "a" * 64

        comparison = ap.compare_reviewer_capabilities(current, baseline)
        markdown = ap.render_reviewer_capability_comparison(comparison)

        self.assertTrue(comparison["same_artifact"])
        self.assertIn("Same artifact", markdown)
        self.assertIn(
            "cannot be attributed to different artifact bytes",
            markdown,
        )

    def test_baseline_loader_rejects_oversized_input_before_reading(self) -> None:
        with patch(
            "reviewer_capability_comparison.os.path.getsize",
            return_value=(64 * 1024 * 1024) + 1,
        ):
            with self.assertRaisesRegex(ValueError, "maximum"):
                ap.load_baseline_report("oversized.json")


if __name__ == "__main__":
    unittest.main()
