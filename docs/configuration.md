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
exclude: []
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

The default policy has no path excludes. Full scans include `.git`, dependency folders, generated folders, large files, and binary-looking files unless you add project-specific `exclude` entries.
