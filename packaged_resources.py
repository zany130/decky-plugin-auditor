"""Locate non-Python files shipped with the installed auditor distribution."""

from __future__ import annotations

from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path, PurePosixPath

_DISTRIBUTION_NAME = "decky-plugin-auditor"


def resolve_distribution_file(filename: str, module_file: str) -> Path:
    """Resolve a resource beside source modules or from an installed wheel.

    Source checkouts keep resources beside the flat modules. Wheels install
    ``data-files`` relative to the environment prefix, so distribution metadata
    is used as a portable fallback instead of assuming a Python-version-specific
    site-packages path.
    """
    adjacent = Path(module_file).resolve().with_name(filename)
    if adjacent.is_file():
        return adjacent

    try:
        installed = distribution(_DISTRIBUTION_NAME)
    except PackageNotFoundError:
        return adjacent

    for entry in installed.files or ():
        if PurePosixPath(str(entry)).name != filename:
            continue
        candidate = Path(installed.locate_file(entry)).resolve()
        if candidate.is_file():
            return candidate

    return adjacent
