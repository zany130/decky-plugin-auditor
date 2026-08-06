#!/usr/bin/env python3
"""Installed command-line entry point for Decky Plugin Auditor.

This module intentionally delegates to the validated compatibility entry point
in :mod:`audit_plugins`. Keeping the delegation thin lets installed users call
``decky-audit`` without changing scanner installation order, report output, or
the historical Python import surface.
"""

from __future__ import annotations

from collections.abc import Sequence


def main(argv: Sequence[str] | None = None) -> int:
    """Run the auditor CLI and return its process-style exit code."""
    import audit_plugins

    resolved_argv = list(argv) if argv is not None else None
    return audit_plugins.main(resolved_argv)


if __name__ == "__main__":
    raise SystemExit(main())
