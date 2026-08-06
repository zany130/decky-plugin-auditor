# Decky Plugin Auditor

Static security auditing and reviewer-oriented evidence for Decky Loader plugins.

The auditor inspects plugin release artifacts and corresponding source without importing or executing plugin code. Its goal is to help reviewers answer:

> What can this plugin do, what evidence supports that conclusion, and what changed from the version previously accepted?

## Current status

This repository is the history-preserving extraction of the auditor previously developed inside [`zany130/decky-plugins-extended`](https://github.com/zany130/decky-plugins-extended).

The initial `main` branch intentionally preserves the previous behavior and flat script layout. Repository cleanup, packaging, reviewer capability grouping, and update-aware comparisons will be introduced through separate changes after parity is verified.

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

External scanners degrade gracefully when optional, according to `security-policy.yml`. Plugin code is never imported or executed by the auditor.

## Requirements

- Python 3.10 or newer
- [`uv`](https://docs.astral.sh/uv/) for the documented commands
- a GitHub token for repository and release API access

Optional scanners used by the complete CI workflow include ClamAV, Trivy, and Semgrep.

## Setup

```bash
uv sync
export GITHUB_TOKEN="your-token"
```

## Usage

Audit one repository:

```bash
uv run python audit_plugins.py \
  --repository https://github.com/owner/repository \
  --output-dir security-reports
```

Audit all repositories in a supplied list:

```bash
uv run python audit_plugins.py \
  --all \
  --plugins-file additional_plugins.txt \
  --output-dir security-reports
```

Audit repositories changed relative to another Git ref:

```bash
uv run python audit_plugins.py \
  --changed \
  --plugins-file additional_plugins.txt \
  --base-ref origin/main \
  --output-dir security-reports
```

Run the unit tests:

```bash
GITHUB_TOKEN=test-token uv run python -m unittest discover -s tests -v
```

Reports are written as structured JSON and reviewer-readable Markdown.

## Configuration boundary

The extracted baseline temporarily includes `additional_plugins.txt`, `security-policy.yml`, and `security-allowlist.yml` so its output can be compared directly with the original repository.

Long term:

- this repository owns the generic audit engine, schemas, scanner integrations, and report generation;
- consuming stores or review systems own repository lists, acceptance policy, allowlists, scheduling, and retention decisions.

Those inputs will move back to the consumer only after report parity is demonstrated.

## Roadmap

1. Verify structural, unit-test, and report parity with the original auditor.
2. Add a stable package and CLI boundary without changing report behavior.
3. Group raw findings into reviewer-oriented capability questions.
4. Compare submissions against previously accepted versions.
5. Expose reusable GitHub Action and workflow integrations.
6. Revisit optional deep native-binary analysis after its runtime and process-management issues are resolved.

## Security model

The auditor performs static inspection only. It treats release artifacts and source repositories as untrusted input and does not import or execute plugin code. Findings are reviewer evidence, not proof that a plugin is malicious or safe.

## License and provenance

The extracted history currently retains the MIT license and copyright notice from `decky-plugins-extended`. Any future license change will be handled explicitly in a separate change while preserving the rights and notices attached to previously published code.
