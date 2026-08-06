"""Tests for the installed ``decky-audit`` command boundary."""

from __future__ import annotations

import unittest
from unittest.mock import patch

import decky_audit_cli


class DeckyAuditCliTests(unittest.TestCase):
    def test_main_delegates_arguments_and_exit_code_to_validated_entry_point(self) -> None:
        argv = [
            "--repository",
            "https://github.com/example/plugin",
            "--output-dir",
            "reports",
        ]

        with patch("audit_plugins.main", return_value=3) as audit_main:
            result = decky_audit_cli.main(argv)

        self.assertEqual(result, 3)
        audit_main.assert_called_once_with(argv)

    def test_main_preserves_sys_argv_mode(self) -> None:
        with patch("audit_plugins.main", return_value=0) as audit_main:
            result = decky_audit_cli.main()

        self.assertEqual(result, 0)
        audit_main.assert_called_once_with(None)


if __name__ == "__main__":
    unittest.main()
