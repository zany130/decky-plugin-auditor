"""Regression coverage for PR review hardening of baseline errors."""

from __future__ import annotations

import json
import os
import tempfile
import unittest

import audit_plugins as ap


class ReviewerCapabilityComparisonReviewFixTests(unittest.TestCase):
    def test_duplicate_baseline_repository_does_not_leak_raw_value_to_logs(self) -> None:
        secret = "ghp_" + ("A" * 36)
        payload = {
            "reports": [
                {"repository": "https://github.com/example/plugin"},
                {
                    "repository": (
                        "https://github.com/example/plugin/"
                        f"{secret}\n::error::forged-log-entry"
                    )
                },
            ]
        }

        with tempfile.TemporaryDirectory() as temp_dir:
            path = os.path.join(temp_dir, "baseline.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(payload, handle)

            with self.assertLogs("audit_plugins", level="ERROR") as logs:
                result = ap.main(
                    [
                        "--repository",
                        "https://github.com/example/plugin",
                        "--baseline-report",
                        path,
                    ]
                )

        rendered = "\n".join(logs.output)
        self.assertEqual(result, 2)
        self.assertIn(
            "baseline contains more than one report for the same repository",
            rendered,
        )
        self.assertNotIn(secret, rendered)
        self.assertNotIn("forged-log-entry", rendered)


if __name__ == "__main__":
    unittest.main()
