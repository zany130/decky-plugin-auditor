"""Consumer-owned configuration boundary for the installed auditor CLI.

The validated audit engine historically lived inside a Decky store repository
and therefore defaulted to store-local filenames.  Installed consumers should
not accidentally read configuration from their current working directory.
This module keeps the core behavior intact while making those ownership rules
explicit for the ``decky-audit`` command.
"""

from __future__ import annotations

import argparse
import logging
import sys
import tempfile
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType

log = logging.getLogger("audit_plugins")


def _has_option(argv: Sequence[str], option: str) -> bool:
    return option in argv or any(arg.startswith(f"{option}=") for arg in argv)


def _help_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="decky-audit",
        description="Static security audit for Decky Loader plugin releases.",
    )
    mode_group = parser.add_mutually_exclusive_group(required=True)
    mode_group.add_argument(
        "--all",
        action="store_true",
        help="Audit every repository in the consumer-supplied plugin list",
    )
    mode_group.add_argument(
        "--changed",
        action="store_true",
        help="Audit repositories changed relative to a Git base ref",
    )
    mode_group.add_argument(
        "--repository",
        metavar="URL",
        help="Audit one explicit repository URL",
    )
    parser.add_argument(
        "--plugins-file",
        metavar="PATH",
        help="Plugin list owned by the consumer; required with --all or --changed",
    )
    parser.add_argument(
        "--base-ref",
        default="HEAD~1",
        help="Git ref to diff against for --changed mode (default: HEAD~1)",
    )
    parser.add_argument(
        "--policy",
        metavar="PATH",
        help="Consumer policy YAML; built-in report-only policy when omitted",
    )
    parser.add_argument(
        "--allowlist",
        metavar="PATH",
        help="Consumer allowlist YAML; empty allowlist when omitted",
    )
    parser.add_argument(
        "--baseline-report",
        metavar="PATH",
        help=(
            "Optional previous audit JSON selected by the consumer; compare matching "
            "reviewer capability summaries without inferring acceptance state"
        ),
    )
    parser.add_argument(
        "--output-dir",
        default="security-reports",
        help="Output directory for reports (default: security-reports)",
    )
    parser.add_argument(
        "--cache-dir",
        default=".audit-cache",
        help="Cache directory (default: .audit-cache)",
    )
    parser.add_argument(
        "--skip-cache",
        action="store_true",
        help="Bypass cached audit results",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable debug logging",
    )
    return parser


def run(core: ModuleType, argv: Sequence[str] | None = None) -> int:
    """Run the validated core with consumer-owned configuration semantics."""
    resolved = list(argv) if argv is not None else list(sys.argv[1:])

    if "--help" in resolved or "-h" in resolved:
        _help_parser().print_help()
        return 0

    list_mode = "--all" in resolved or "--changed" in resolved
    if list_mode and not _has_option(resolved, "--plugins-file"):
        log.error("--plugins-file is required with --all or --changed")
        return 2

    # Empty temporary YAML documents make the existing loaders select their
    # built-in policy and empty allowlist without consulting similarly named
    # files in the consumer's current working directory.
    with tempfile.TemporaryDirectory(prefix="decky-audit-config-") as temp_dir:
        normalized = list(resolved)
        root = Path(temp_dir)

        if not _has_option(normalized, "--policy"):
            policy_path = root / "built-in-policy.yml"
            policy_path.write_text("{}\n", encoding="utf-8")
            normalized.extend(("--policy", str(policy_path)))

        if not _has_option(normalized, "--allowlist"):
            allowlist_path = root / "empty-allowlist.yml"
            allowlist_path.write_text(
                'version: "1"\nexceptions: []\n',
                encoding="utf-8",
            )
            normalized.extend(("--allowlist", str(allowlist_path)))

        return int(core.main(normalized))
