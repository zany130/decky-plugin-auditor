# Decky Plugin Auditor

Static security auditing and reviewer-oriented evidence for Decky Loader plugins.

The auditor inspects plugin release artifacts and corresponding source without importing or executing plugin code. Its goal is to help reviewers answer:

> What can this plugin do, what evidence supports that conclusion, and what changed from the version previously accepted?

## Current status

This repository is the history-preserving extraction of the auditor previously developed inside [`zany130/decky-plugins-extended`](https://github.com/zany130/decky-plugins-extended).

`main` preserves the auditor behavior validated against the original repository. The project now has an installable `decky-audit` command and an explicit boundary between the reusable engine and configuration owned by a consuming store or review system.

Experimental capa-based native-binary capability analysis is preserved separately in draft PR #2 and is not part of the stable baseline.

## What it currently audits

- release archive safety and structure
- malware signatures through ClamAV
- dependency and artifact vulnerabilities through Trivy
- Semgrep static-analysis rules
- release artifact versus exact source comparison
- release-only or modified executable files
- network destinations with source provenance
- credentials and sensitive-data exposure
- behavioral heuristics such as command execution and system modification
- immutable source links
- native-binary inventory and hashes
- JSON and Markdown evidence reports

External scanners degrade gracefully when optional according to the selected policy. Plugin code is never imported or executed by the auditor.

## Requirements

- Python 3.10 or newer
- [`uv`](https://docs.astral.sh/uv/) for the documented development commands
- a GitHub token for repository and release API access

Optional scanners used by the complete CI workflow include ClamAV, Trivy, and Semgrep.

## Setup

```bash
uv sync
export GITHUB_TOKEN="your-token"
```

## Usage

The installed project exposes `decky-audit`. The historical `python audit_plugins.py` entry point remains available for migration compatibility.

Audit one repository without any store configuration files:

```bash
uv run decky-audit \
  --repository https://github.com/owner/repository \
  --output-dir security-reports
```

Audit all repositories in a consumer-owned list:

```bash
uv run decky-audit \
  --all \
  --plugins-file config/plugins.txt \
  --policy config/security-policy.yml \
  --allowlist config/security-allowlist.yml \
  --output-dir security-reports
```

Audit repositories changed relative to another Git ref:

```bash
uv run decky-audit \
  --changed \
  --plugins-file config/plugins.txt \
  --base-ref origin/main \
  --output-dir security-reports
```

`--plugins-file` is required with `--all` and `--changed`. When `--policy` is omitted, the installed command uses its built-in report-only policy. When `--allowlist` is omitted, it uses an empty allowlist. It does not automatically consume similarly named files from the current working directory.

A complete example is available in [`examples/consumer`](examples/consumer).

Legacy compatibility invocation:

```bash
uv run python audit_plugins.py \
  --repository https://github.com/owner/repository \
  --output-dir security-reports
```

Run the unit tests:

```bash
GITHUB_TOKEN=test-token uv run python -m unittest discover -s tests -v
```

Reports are written as structured JSON and reviewer-readable Markdown.

## Configuration boundary

The reusable auditor owns:

- the audit engine and report schemas
- scanner integrations and static-analysis rules
- built-in report-only policy defaults
- report generation and cache behavior

A consuming store or review system owns:

- the repository list
- acceptance and enforcement policy
- allowlist decisions and approvals
- schedules, retention, and review workflow integration

The root `additional_plugins.txt`, `security-policy.yml`, and `security-allowlist.yml` files remain temporarily for the legacy scheduled migration check. They are not installed command defaults and will move back to the consuming store after its workflow is switched to the standalone CLI.

## Roadmap

1. Integrate the standalone CLI into the consuming Decky store.
2. Remove the temporary store-owned migration inputs from this repository.
3. Complete the planned Apache-2.0 licensing change.
4. Group raw findings into reviewer-oriented capability questions.
5. Compare submissions against previously accepted versions.
6. Expose reusable GitHub Action and official Decky review integrations.
7. Revisit optional deep native-binary analysis after its runtime and process-management issues are resolved.

## Security model

The auditor performs static inspection only. It treats release artifacts and source repositories as untrusted input and does not import or execute plugin code. Findings are reviewer evidence, not proof that a plugin is malicious or safe.

## License and provenance

The extracted history currently retains the MIT license and copyright notice from `decky-plugins-extended`. Any future license change will be handled explicitly in a separate change while preserving the rights and notices attached to previously published code.
