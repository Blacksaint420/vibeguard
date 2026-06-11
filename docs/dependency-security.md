# Dependency Security

VibeGuard checks dependency manifests and component references during full-repository scans and explicit diff scans. It does not currently resolve and audit the entire transitive dependency tree.

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

The default vulnerability provider is null/offline. This keeps the tool local-first.

Optional providers:

```bash
vibeguard check --vuln-provider null
vibeguard check --vuln-provider mock
vibeguard check --vuln-provider osv
```

`mock` is for local tests. `osv` sends dependency names and versions to OSV, but does not upload source code or repository contents.

Current dependency findings focus on review risks: broad ranges, unpinned versions, visible downgrades, suspicious names, lifecycle install scripts, lockfile-only changes in diff mode, and optional vulnerability matches.
