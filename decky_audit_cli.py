#!/usr/bin/env python3
"""Installed command-line entry point for Decky Plugin Auditor.

The installed command delegates audit behavior to the validated compatibility
entry point while applying consumer-owned configuration semantics. This keeps
scanner installation order and report output stable without assuming the
current directory belongs to a particular Decky store.
"""

from __future__ import annotations

from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Run the installed auditor CLI and return its process-style exit code."""
    import audit_plugins
    from consumer_configuration import run

    return run(audit_plugins, argv)


if __name__ == "__main__":
    raise SystemExit(main())
