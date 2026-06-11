# Dependency Security

VibeGuard checks dependency changes in the diff, not the entire dependency tree.

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

The vulnerability provider interface is present, but the default provider is null/offline. This keeps the tool local-first. A future OSV-compatible provider can be added without changing scanner output.

Current dependency findings focus on review risks: broad ranges, unpinned versions, visible downgrades, suspicious names, and lockfile-only changes.

