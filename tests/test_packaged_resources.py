"""Tests for resources included in the installable auditor wheel."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path, PurePosixPath
from unittest.mock import patch

import packaged_resources


class _FakeDistribution:
    def __init__(self, resource: Path) -> None:
        self._resource = resource
        self.files = [PurePosixPath("../../../semgrep-rules.yml")]

    def locate_file(self, _entry: PurePosixPath) -> Path:
        return self._resource


class PackagedResourceTests(unittest.TestCase):
    def test_adjacent_source_resource_takes_precedence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module_file = root / "semgrep_source_scanning.py"
            resource = root / "semgrep-rules.yml"
            module_file.write_text("", encoding="utf-8")
            resource.write_text("rules: []\n", encoding="utf-8")

            resolved = packaged_resources.resolve_distribution_file(
                "semgrep-rules.yml",
                str(module_file),
            )

        self.assertEqual(resolved, resource.resolve())

    def test_installed_distribution_resource_is_used_as_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            module_file = root / "site-packages" / "semgrep_source_scanning.py"
            module_file.parent.mkdir()
            module_file.write_text("", encoding="utf-8")
            installed_resource = root / "semgrep-rules.yml"
            installed_resource.write_text("rules: []\n", encoding="utf-8")

            with patch(
                "packaged_resources.distribution",
                return_value=_FakeDistribution(installed_resource),
            ):
                resolved = packaged_resources.resolve_distribution_file(
                    "semgrep-rules.yml",
                    str(module_file),
                )

        self.assertEqual(resolved, installed_resource.resolve())


if __name__ == "__main__":
    unittest.main()
