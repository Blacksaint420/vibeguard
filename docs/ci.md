# CI

VibeGuard is designed for local use first, but it can also summarize pull request diffs in CI.

```bash
vibeguard check --base origin/main --format sarif
vibeguard check --base origin/main --format markdown
```

For full repository CI scans:

```bash
vibeguard check --format sarif
```

SARIF output is suitable for code-scanning style ingestion. Markdown output is suitable for pull request comments.

This version does not upload source code or dependency manifests.
