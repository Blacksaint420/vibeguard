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

For an HTML artifact:

```bash
vibeguard check --format html > vibeguard-report.html
```

SARIF output is suitable for code-scanning style ingestion. Markdown output is suitable for pull request comments.

This version does not upload source code. OSV vulnerability lookup is opt-in with `--vuln-provider osv`.

## GitHub Action

The repository also ships a composite action that generates AI BOM, agent graph, and SARIF files from the action checkout. It does not require VibeGuard to be published to npm.

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v6
  - uses: actions/setup-node@v6
    with:
      node-version: "24.x"
  - id: vibeguard
    uses: Blacksaint420/vibeguard@v0.1.0
    with:
      path: "."
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.vibeguard.outputs.sarif-file }}
      category: vibeguard
  - name: Fail on blocking findings
    if: steps.vibeguard.outputs.exit-code == '1'
    run: exit 1
```

Set `fail-on-findings: "true"` only when you do not need later workflow steps, such as SARIF upload, to run after blocking findings.

## Significant Main-Branch Changes

The `Main Change Readiness` workflow runs on pushes to `main` when meaningful files change, including source code, tests, schemas, package metadata, policies, docs, workflows, and release files. It runs the full verification path, checks the local package artifact, generates SARIF, AI BOM, and agent graph artifacts, uploads SARIF to code scanning, and fails the run when VibeGuard reports blocking findings.
