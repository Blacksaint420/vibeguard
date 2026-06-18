# Dependency Security

VibeGuard checks dependency manifests and component references during full-repository scans and explicit diff scans. Default LLM03 supply-chain findings require a confirmed vulnerable package/version match from a vulnerability provider.

Supported first-version inputs:

- `package.json`
- `package-lock.json`
- `yarn.lock`
- `pnpm-lock.yaml`
- `requirements.txt`
- `pyproject.toml`
- `poetry.lock`
- Dockerfile `FROM` lines
- GitHub Actions `uses:` lines

The default vulnerability provider is null/offline. This keeps the tool local-first and means no LLM03 vulnerable-package findings are produced unless you enable a provider.

Optional providers:

```bash
vibeguard check --vuln-provider null
vibeguard check --vuln-provider mock
vibeguard check --vuln-provider osv
```

`mock` is for local tests. `osv` sends dependency names and versions to OSV, but does not upload source code or repository contents.

Provider reliability controls:

```bash
vibeguard check --vuln-provider osv --vuln-provider-fail-mode warn
vibeguard check --vuln-provider osv --vuln-provider-fail-mode fail
vibeguard check --vuln-provider osv --vuln-provider-timeout-ms 10000
vibeguard check --vuln-provider osv --vuln-provider-concurrency 4
```

The default fail mode is `warn`: provider timeouts, HTTP failures, and malformed provider errors are reported as scan warnings while the local scan continues. Use `--vuln-provider-fail-mode fail` only for strict environments that prefer fail-fast network intelligence.

Default dependency findings focus on confirmed vulnerable versions only. Review signals such as broad ranges, unpinned versions, visible downgrades, suspicious names, lifecycle install scripts, and lockfile-only changes are available with `--min-confidence medium`, but they are not treated as default LLM03 vulnerabilities.
