# Repository Management

This document records the GitHub repository settings and maintainer automation for VibeGuard.

## GitHub About Section

Recommended repository description:

```text
Local-first AI security CLI for scanning AI-built apps, generating AI BOMs, agent capability graphs, SARIF, and GRC-ready risk evidence.
```

Recommended topics:

```text
ai-security, llm-security, aibom, agent-security, appsec, sast, sarif, owasp-llm, cli, grc
```

Recommended website:

```text
https://github.com/Blacksaint420/vibeguard#readme
```

Enable private vulnerability reporting from the repository security settings before promoting the project publicly.

## Main Change Readiness Automation

The `Main Change Readiness` workflow runs on pushes to `main` when meaningful files change:

- Source packages under `packages/**`
- Tests, scripts, schemas, examples, and benchmarks
- Package metadata and lockfiles
- VibeGuard policy/config files
- GitHub Actions workflows and action metadata
- Public docs and release/security files

The workflow verifies the repository by running tests, building the compiled CLI, checking the local package artifact, generating SARIF, AI BOM, and agent graph artifacts, uploading SARIF to GitHub code scanning, and failing on blocking VibeGuard findings.

## Branch Protection Recommendation

After the first successful Actions run, protect `main` with required checks:

- `CI`
- `VibeGuard Code Scanning`
- `Main Change Readiness`

Require pull requests before merging once more than one maintainer is active.
