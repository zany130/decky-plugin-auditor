# Consumer configuration example

These files demonstrate the configuration owned by a store, review system, or
other consumer of the installed `decky-audit` command.

```bash
decky-audit \
  --all \
  --plugins-file examples/consumer/plugins.txt \
  --policy examples/consumer/policy.yml \
  --allowlist examples/consumer/allowlist.yml \
  --output-dir security-reports
```

`--plugins-file` is required for `--all` and `--changed`. The policy and
allowlist are optional: omitting them selects the auditor's built-in report-only
policy and an empty allowlist. Production consumers should normally keep all
three files in the consuming repository so review decisions remain separate
from the reusable audit engine.
