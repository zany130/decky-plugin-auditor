import json
import os
import tempfile
import unittest
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

import github_step_summary as summary


class GithubStepSummaryTests(unittest.TestCase):
    def report(self, index=0, *, attention=False, same_artifact=True):
        capabilities = []
        if attention:
            capabilities = [
                {
                    "id": "network_communication",
                    "title": "Network communication",
                    "summary": "network destinations +438/-0",
                    "reviewer_attention": True,
                    "details": {
                        # Compact summaries must not dump the huge detail list.
                        "added_destinations": [f"host-{i}.example" for i in range(1000)]
                    },
                }
            ]
        return {
            "repository": f"https://github.com/example/plugin-{index}",
            "release": f"v1.{index}.0",
            "final_classification": "MANUAL_REVIEW",
            "risk_score": index,
            "reviewer_capability_comparison": {
                "status": "compared",
                "changed_count": 1 if attention else 0,
                "attention_count": 1 if attention else 0,
                "same_artifact": same_artifact,
                "capabilities": capabilities,
            },
        }

    def test_compact_summary_keeps_all_rows_without_dumping_large_details(self):
        payload = {"reports": [self.report(i, attention=(i == 7)) for i in range(50)]}

        rendered = summary.compact_summary(payload)

        self.assertLessEqual(len(rendered.encode("utf-8")), summary.SUMMARY_SOFT_LIMIT_BYTES)
        for i in range(50):
            self.assertIn(f"https://github.com/example/plugin-{i}", rendered)
        self.assertIn("Security-relevant baseline changes", rendered)
        self.assertIn("network destinations +438/-0", rendered)
        self.assertNotIn("host-999.example", rendered)

    def test_compact_summary_redacts_and_escapes_dynamic_values(self):
        secret = "ghp_" + ("A" * 36)
        report = self.report(1, attention=True)
        report["repository"] = f"https://github.com/{secret}/bad|repo"
        report["release"] = "v1.0_[unsafe]"

        rendered = summary.compact_summary({"reports": [report]})

        self.assertNotIn(secret, rendered)
        self.assertIn("REDACTED", rendered)
        self.assertIn("\\|", rendered)
        self.assertIn("\\_", rendered)

    def _fake_core(self, detailed_text):
        core = ModuleType("fake_audit_core")
        core.DEFAULT_OUTPUT_DIR = "security-reports"

        def original_main(argv=None):
            tokens = list(argv or [])
            output_dir = Path(tokens[tokens.index("--output-dir") + 1])
            output_dir.mkdir(parents=True, exist_ok=True)
            with open(output_dir / "security-report.json", "w", encoding="utf-8") as handle:
                json.dump({"reports": [self.report(1, attention=True)]}, handle)
            with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
                handle.write(detailed_text)
            return 3

        core.main = original_main
        return core

    def test_install_preserves_small_detailed_summary_and_exit_code(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            actual = Path(temp_dir) / "summary.md"
            output_dir = Path(temp_dir) / "reports"
            core = self._fake_core("small detailed report\n")
            summary.install(core)

            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(actual)}):
                result = core.main(["--output-dir", str(output_dir)])
                self.assertEqual(os.environ["GITHUB_STEP_SUMMARY"], str(actual))

            self.assertEqual(result, 3)
            self.assertEqual(actual.read_text(encoding="utf-8"), "small detailed report\n")

    def test_install_replaces_oversized_detail_with_compact_summary(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            actual = Path(temp_dir) / "summary.md"
            output_dir = Path(temp_dir) / "reports"
            huge = "x" * (summary.SUMMARY_SOFT_LIMIT_BYTES + 1000)
            core = self._fake_core(huge)
            summary.install(core)

            with patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(actual)}):
                result = core.main(["--output-dir", str(output_dir)])

            rendered = actual.read_text(encoding="utf-8")
            self.assertEqual(result, 3)
            self.assertLessEqual(len(rendered.encode("utf-8")), summary.SUMMARY_SOFT_LIMIT_BYTES)
            self.assertIn("Security Audit Summary", rendered)
            self.assertIn("https://github.com/example/plugin-1", rendered)
            self.assertNotIn(huge[:1000], rendered)


if __name__ == "__main__":
    unittest.main()
