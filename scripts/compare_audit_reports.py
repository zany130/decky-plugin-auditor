#!/usr/bin/env python3
"""Compare auditor JSON and Markdown outputs while ignoring run timestamps."""

from __future__ import annotations

import argparse
import difflib
import json
import sys
from pathlib import Path
from typing import Any

_DYNAMIC_JSON_KEYS = {"audit_timestamp", "generated_at"}
_DYNAMIC_PLACEHOLDER = "<dynamic>"


def _normalise_json(value: Any) -> Any:
    if isinstance(value, dict):
        normalised: dict[str, Any] = {}
        for key, item in sorted(value.items()):
            if key in _DYNAMIC_JSON_KEYS:
                normalised[key] = _DYNAMIC_PLACEHOLDER
            else:
                normalised[key] = _normalise_json(item)
        return normalised
    if isinstance(value, list):
        return [_normalise_json(item) for item in value]
    return value


def _normalise_markdown(text: str) -> str:
    lines: list[str] = []
    for line in text.splitlines():
        if line.startswith("Generated: "):
            lines.append("Generated: <dynamic>")
        elif line.startswith("| Audit Timestamp | "):
            lines.append("| Audit Timestamp | <dynamic> |")
        else:
            lines.append(line.rstrip())
    return "\n".join(lines).rstrip() + "\n"


def _unified_diff(old: str, new: str, old_name: str, new_name: str) -> str:
    return "".join(
        difflib.unified_diff(
            old.splitlines(keepends=True),
            new.splitlines(keepends=True),
            fromfile=old_name,
            tofile=new_name,
        )
    )


def compare_reports(old_dir: Path, new_dir: Path) -> int:
    old_json_path = old_dir / "security-report.json"
    new_json_path = new_dir / "security-report.json"
    old_md_path = old_dir / "security-report.md"
    new_md_path = new_dir / "security-report.md"

    for path in (old_json_path, new_json_path, old_md_path, new_md_path):
        if not path.is_file():
            print(f"ERROR: required report is missing: {path}", file=sys.stderr)
            return 2

    old_json = _normalise_json(json.loads(old_json_path.read_text(encoding="utf-8")))
    new_json = _normalise_json(json.loads(new_json_path.read_text(encoding="utf-8")))
    old_json_text = json.dumps(old_json, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    new_json_text = json.dumps(new_json, indent=2, sort_keys=True, ensure_ascii=False) + "\n"

    old_md = _normalise_markdown(old_md_path.read_text(encoding="utf-8"))
    new_md = _normalise_markdown(new_md_path.read_text(encoding="utf-8"))

    failed = False
    if old_json_text != new_json_text:
        failed = True
        print("ERROR: structured JSON reports differ after timestamp normalisation.")
        print(
            _unified_diff(
                old_json_text,
                new_json_text,
                "legacy/security-report.json",
                "installed/security-report.json",
            )
        )

    if old_md != new_md:
        failed = True
        print("ERROR: Markdown reports differ after timestamp normalisation.")
        print(
            _unified_diff(
                old_md,
                new_md,
                "legacy/security-report.md",
                "installed/security-report.md",
            )
        )

    if failed:
        return 1

    reports = new_json.get("reports", []) if isinstance(new_json, dict) else []
    print(
        "CLI parity passed: JSON and Markdown match for "
        f"{len(reports)} report(s), excluding generated timestamps."
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Compare legacy-script and installed-CLI report directories."
    )
    parser.add_argument("old_dir", type=Path)
    parser.add_argument("new_dir", type=Path)
    args = parser.parse_args()
    return compare_reports(args.old_dir, args.new_dir)


if __name__ == "__main__":
    raise SystemExit(main())
