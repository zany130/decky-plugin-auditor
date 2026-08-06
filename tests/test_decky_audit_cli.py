"""Tests for the installed ``decky-audit`` command boundary."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import audit_plugins
import decky_audit_cli


class DeckyAuditCliTests(unittest.TestCase):
    def test_main_delegates_arguments_and_exit_code_to_consumer_boundary(self) -> None:
        argv = [
            "--repository",
            "https://github.com/example/plugin",
            "--output-dir",
            "reports",
        ]

        with patch("consumer_configuration.run", return_value=3) as run:
            result = decky_audit_cli.main(argv)

        self.assertEqual(result, 3)
        run.assert_called_once_with(audit_plugins, argv)

    def test_main_preserves_sys_argv_mode(self) -> None:
        with patch("consumer_configuration.run", return_value=0) as run:
            result = decky_audit_cli.main()

        self.assertEqual(result, 0)
        run.assert_called_once_with(audit_plugins, None)


if __name__ == "__main__":
    unittest.main()
