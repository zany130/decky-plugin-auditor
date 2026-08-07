# Decky Plugin Auditor

Static security auditing and reviewer-oriented evidence for Decky Loader plugins.

The auditor inspects plugin release artifacts and corresponding source without importing or executing plugin code. Its goal is to help reviewers answer:

> What can this plugin do, what evidence supports that conclusion, and what changed from the version previously accepted?

## Current status

This repository is the history-preserving extraction of the auditor previously developed inside [`zany130/decky-plugins-extended`](https://github.com/zany130/decky-plugins-extended).

`main` preserves the auditor behavior validated against the original repository. The project has an installable `decky-audit` command and an explicit boundary between the reusable engine and configuration owned by a consuming store or review system. `decky-plugins-extended` now consumes the standalone auditor from an immutable commit while keeping its repository list, policy, allowlist, schedule, cache, and report-retention decisions in the store repository.

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
- reviewer-oriented capability summaries derived from the underlying evidence
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

Reports are written as structured JSON and reviewer-readable Markdown. The JSON report includes a stable `reviewer_capabilities` list plus `reviewer_capabilities_schema_version`, and the Markdown report surfaces the same capability questions before the raw findings. Capability summaries are derived from existing findings and structured evidence only; they do not change classification, risk scoring, allowlist behavior, or enforcement.

The capability layer distinguishes `observed`, `not_observed`, and `unknown`. `not_observed` means relevant audit coverage completed without supporting evidence. `unknown` means the relevant scanner, exact-source comparison, or broader audit coverage was incomplete or unavailable. Neither status proves that a capability is impossible. Malware and known vulnerabilities are reported as separate capability questions so ClamAV coverage is not conflated with Trivy/OSV-style vulnerability coverage.

## Configuration boundary

The reusable auditor owns:

- the audit engine and report schemas
- scanner integrations and static-analysis rules
- built-in report-only policy defaults
- report generation and cache behavior
- package, unit, rule-control, and single-plugin smoke validation

A consuming store or review system owns:

- the repository list
- acceptance and enforcement policy
- allowlist decisions and approvals
- schedules and audit cadence
- cache and report retention policy
- review workflow integration

Consumer-owned configuration is supplied explicitly at runtime. The standalone repository keeps only generic examples under [`examples/consumer`](examples/consumer); it does not maintain a store catalog or scheduled full-store audit.

## Roadmap

1. Compare submissions against previously accepted versions, including capability-level changes.
2. Expose reusable GitHub Action and official Decky review integrations.
3. Add reviewer history/persistence and a documented threat model.
4. Revisit optional deep native-binary analysis after its runtime and process-management issues are resolved.

## Security model

The auditor performs static inspection only. It treats release artifacts and source repositories as untrusted input and does not import or execute plugin code. Findings and reviewer capability summaries are evidence, not proof that a plugin is malicious or safe.

## License and provenance

Decky Plugin Auditor is licensed under the [Apache License 2.0](LICENSE). Project attribution and extraction provenance are recorded in [NOTICE](NOTICE).

The auditor was originally designed and implemented by Andres Ortiz inside [`zany130/decky-plugins-extended`](https://github.com/zany130/decky-plugins-extended), then extracted into this repository with its relevant development history preserved.

The preserved git history also contains earlier parent-store commits unrelated to the current auditor distribution. Historical commits attributed to `beallio` changed the former store-owned `additional_plugins.txt` catalog; that catalog was removed from the standalone repository before this relicensing. The current standalone package boundary contains the auditor implementation, scanner integrations and rules, reusable examples, and tests maintained here, while consumer repository lists, policy, allowlists, schedules, caches, and retention remain external.

Package validation verifies that the wheel and source distribution declare `Apache-2.0` and include both `LICENSE` and `NOTICE`.
