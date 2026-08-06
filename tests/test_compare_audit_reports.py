"""Regression tests for extraction parity report normalisation."""

from __future__ import annotations

import importlib.util
import unittest
from pathlib import Path


_SCRIPT_PATH = (
    Path(__file__).resolve().parents[1] / "scripts" / "compare_audit_reports.py"
)
_SPEC = importlib.util.spec_from_file_location("compare_audit_reports", _SCRIPT_PATH)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"Could not load parity helper from {_SCRIPT_PATH}")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)


class NormaliseJsonTests(unittest.TestCase):
    def test_timestamp_values_are_replaced_but_fields_are_preserved(self) -> None:
        old = {
            "generated_at": "2026-08-06T03:00:00Z",
            "reports": [
                {
                    "audit_timestamp": "2026-08-06T03:00:01Z",
                    "final_classification": "PASS",
                }
            ],
        }
        new = {
            "generated_at": "2026-08-06T03:10:00Z",
            "reports": [
                {
                    "audit_timestamp": "2026-08-06T03:10:01Z",
                    "final_classification": "PASS",
                }
            ],
        }

        normalised_old = _MODULE._normalise_json(old)
        normalised_new = _MODULE._normalise_json(new)

        self.assertEqual(normalised_old, normalised_new)
        self.assertEqual(normalised_old["generated_at"], "<dynamic>")
        self.assertEqual(
            normalised_old["reports"][0]["audit_timestamp"], "<dynamic>"
        )

    def test_missing_timestamp_field_still_breaks_parity(self) -> None:
        with_timestamp = {
            "generated_at": "2026-08-06T03:00:00Z",
            "reports": [{"audit_timestamp": "2026-08-06T03:00:01Z"}],
        }
        without_timestamp = {
            "reports": [{}],
        }

        self.assertNotEqual(
            _MODULE._normalise_json(with_timestamp),
            _MODULE._normalise_json(without_timestamp),
        )


if __name__ == "__main__":
    unittest.main()
