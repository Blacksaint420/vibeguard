# Configuration

`vibeguard init` writes `vibeguard.yml`.

Default policy:

```yaml
mode: warn
enabledScanners:
  - code
  - secrets
  - dependencies
  - docker
  - actions
  - sensitive-files
blockSeverities:
  - high
  - critical
include:
  - "**/*"
exclude: []
suppressions: []
minConfidence: high
coverage:
  requireComplete: false
  failOnUnreadable: false
aiGovernance:
  mode: audit
  blockOnDrift: false
```

Suppress a finding by rule and file:

```yaml
suppressions:
  - rule: js-express-route-no-obvious-auth
    file: src/public-healthcheck.ts
    reason: Public unauthenticated health check.
```

The first parser intentionally supports the generated policy shape and simple suppressions without external YAML dependencies.

The default policy has no path excludes. Full scans include `.git`, dependency folders, generated folders, large files, and binary-looking files unless you add project-specific `exclude` entries.

The default policy uses `minConfidence: high` so normal reports focus on likely true positives. Use `minConfidence: medium` or `vibeguard check --min-confidence medium` for broader audit mode.

The generated default `mode: warn` is audit-only. Set `mode: block` when technical findings should affect the process exit code.

## AI BOM Governance

AI governance is audit-only by default. It can compare the current AI BOM with an approved BOM and policy allow/block lists:

```yaml
aiGovernance:
  mode: audit
  approvedBom: .vibeguard/approved-aibom.json
  blockOnDrift: false
  allowedProviders:
    - openai
    - anthropic
  blockedProviders:
    - unknown
  blockedModels:
    - "*-preview"
  blockedCapabilities:
    - shell
    - secret-access
```

Use `mode: block` or `--ai-governance-mode block` only when governance findings should affect the process exit code.

Runtime controls can also be passed on the command line:

```bash
vibeguard check --max-findings 50
vibeguard check --min-confidence high
vibeguard check --strict-coverage
vibeguard check --max-files 10000
vibeguard check --max-file-bytes 1048576
vibeguard check --quiet
vibeguard check --approved-aibom .vibeguard/approved-aibom.json
vibeguard check --ai-policy examples/policies/vibeguard-ai-governance.yml
vibeguard check --ai-governance-mode audit
```

## Coverage

Every scan reports coverage in JSON, risk-json, HTML, Markdown, and table output.

Coverage fields include discovered files, scanned files, skipped files, policy exclusions, binary skips, oversized skips, unreadable files, file-limit status, coverage percent, and status: `complete`, `partial`, or `failed`.

Policy controls:

```yaml
coverage:
  requireComplete: true
  failOnUnreadable: true
  maxFiles: 10000
  maxFileBytes: 1048576
```

`--strict-coverage` exits with code `2` when coverage is incomplete because of tool/config collection limits. `coverage.requireComplete: true` turns incomplete coverage into a blocking policy finding.

Baseline current findings when adopting VibeGuard in an existing repository:

```bash
vibeguard baseline --output vibeguard-baseline.json
vibeguard check --baseline vibeguard-baseline.json
```

Add a reasoned suppression from the CLI:

```bash
vibeguard suppress js-express-route-no-obvious-auth --file src/public-healthcheck.ts --reason "Public unauthenticated health check."
```
