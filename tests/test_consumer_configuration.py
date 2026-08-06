"""Tests for installed consumer-owned configuration behavior."""

from __future__ import annotations

import io
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from consumer_configuration import run


class ConsumerConfigurationTests(unittest.TestCase):
    def test_all_requires_explicit_plugins_file(self) -> None:
        raw_main = Mock(return_value=0)
        core = SimpleNamespace(main=raw_main)

        result = run(core, ["--all"])

        self.assertEqual(result, 2)
        raw_main.assert_not_called()

    def test_changed_requires_explicit_plugins_file(self) -> None:
        raw_main = Mock(return_value=0)
        core = SimpleNamespace(main=raw_main)

        result = run(core, ["--changed", "--base-ref", "origin/main"])

        self.assertEqual(result, 2)
        raw_main.assert_not_called()

    def test_repository_mode_injects_isolated_defaults(self) -> None:
        def raw_main(argv: list[str]) -> int:
            policy_path = Path(argv[argv.index("--policy") + 1])
            allowlist_path = Path(argv[argv.index("--allowlist") + 1])
            self.assertTrue(policy_path.is_file())
            self.assertTrue(allowlist_path.is_file())
            self.assertEqual(policy_path.read_text(encoding="utf-8"), "{}\n")
            self.assertEqual(
                allowlist_path.read_text(encoding="utf-8"),
                'version: "1"\nexceptions: []\n',
            )
            self.assertNotIn("--plugins-file", argv)
            return 3

        core = SimpleNamespace(main=raw_main)
        result = run(
            core,
            ["--repository", "https://github.com/example/plugin"],
        )

        self.assertEqual(result, 3)

    def test_explicit_consumer_configuration_is_preserved(self) -> None:
        argv = [
            "--all",
            "--plugins-file=consumer/plugins.txt",
            "--policy",
            "consumer/policy.yml",
            "--allowlist=consumer/allowlist.yml",
        ]
        raw_main = Mock(return_value=0)
        core = SimpleNamespace(main=raw_main)

        result = run(core, argv)

        self.assertEqual(result, 0)
        raw_main.assert_called_once_with(argv)

    def test_help_uses_installed_cli_contract_without_calling_core(self) -> None:
        raw_main = Mock(return_value=0)
        core = SimpleNamespace(main=raw_main)

        with patch("sys.stdout", new_callable=io.StringIO) as stdout:
            result = run(core, ["--help"])

        self.assertEqual(result, 0)
        self.assertIn("consumer-supplied plugin list", stdout.getvalue())
        self.assertIn("built-in report-only policy", stdout.getvalue())
        raw_main.assert_not_called()


if __name__ == "__main__":
    unittest.main()
