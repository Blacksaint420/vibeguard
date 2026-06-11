# Configuration

`vibeguard init` writes `vibeguard.yml`.

Default policy:

```yaml
mode: block
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
exclude:
  - "node_modules/**"
  - "dist/**"
  - "coverage/**"
suppressions: []
```

Suppress a finding by rule and file:

```yaml
suppressions:
  - rule: js-express-route-no-obvious-auth
    file: src/public-healthcheck.ts
    reason: Public unauthenticated health check.
```

The first parser intentionally supports the generated policy shape and simple suppressions without external YAML dependencies.

