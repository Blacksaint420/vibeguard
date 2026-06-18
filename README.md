# VibeGuard

VibeGuard is a local-first AI security CLI framework for developers, security teams, and GRC teams.

> Check the code your AI just changed before you accept, commit, or merge it.

The guided CLI walks users through developer scans, GRC risk briefings, AI Bill of Materials generation, agent capability graphing, reports, rule explanations, and local health checks. The same engine is still available through explicit commands for automation. Findings are mapped to the OWASP Top 10 for LLM Applications 2025 and other AI security frameworks where applicable, with evidence, attack path, impact, and a concrete fix. It does not upload source code.

## Project Status

VibeGuard is pre-1.0. The CLI is usable for local scans and CI experiments, but rule behavior, report fields, and schema details may change while the project hardens its public release process.

## Install

After the package is published to npm, run it without installing:

```bash
npx --yes vibeguard@latest doctor
npx --yes vibeguard@latest check
```

Or install the CLI globally:

```bash
npm install -g vibeguard
```

For local development from source:

```bash
npm install
npm run build
npm link
```

The published CLI runs from compiled JavaScript in `dist/` and targets Node 20+. The source tests use the local Node runtime.

## Commands

Start the interactive framework:

```bash
vibeguard
```

The framework starts a console. Accept the default target when running from an application repository, or use `set-target` inside the console. You can select options by number or command name:

```text
scan
risk
aibom
graph
full
report
explain
doctor
exit
```

The `graph` command shows an access diagram of what detected AI agents and tools can reach. Markdown graph output also includes a Mermaid diagram for reports.

You can also start the framework with an explicit target:

```bash
vibeguard interactive --target "/Users/you/Projects/CV Maker"
```

Automation commands remain available:

```bash
vibeguard init
vibeguard check
vibeguard check "/Users/you/Projects/CV Maker"
vibeguard check --staged
vibeguard check --base origin/main
vibeguard check --format table
vibeguard check --format json
vibeguard check --format sarif
vibeguard check --format markdown
vibeguard check --format html
vibeguard check --output vibeguard-report.json
vibeguard check --baseline vibeguard-baseline.json
vibeguard check --quiet --max-findings 20 --min-confidence high
vibeguard check --vuln-provider osv
vibeguard aibom --format aibom-json --output vibeguard-aibom.json
vibeguard graph --format graph-json --output vibeguard-agent-graph.json
vibeguard baseline "/Users/you/Projects/CV Maker"
vibeguard report "/Users/you/Projects/CV Maker" --format html --output vibeguard-report.html
vibeguard suppress js-eval --file src/app.js --reason "Accepted generated sandbox"
vibeguard explain js-eval
vibeguard doctor
```

Exit codes:

- `0`: no blocking findings
- `1`: blocking findings found
- `2`: tool, config, or runtime error

## What It Scans

- JavaScript, TypeScript, and Python files for high-confidence insecure code and LLM application patterns.
- OWASP LLM 2025 risks including prompt injection, sensitive information disclosure, vulnerable dependency supply chain, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, and unbounded consumption when there is direct code evidence.
- Concrete tokens, credentials, private keys, and high-confidence PII with masking.
- npm, yarn, pnpm, `requirements.txt`, and `pyproject.toml` dependency manifests.
- Dockerfile base image risks.
- GitHub Actions mutable references and broad permissions.
- Sensitive file path changes such as `.env`, `.npmrc`, private keys, and cloud credentials.

By default, `vibeguard check` walks the full repository, including generated directories, dependency directories, git metadata, large files, and binary-looking files. Use `--staged` or `--base` when you want a focused git-diff scan.

Default reports use `minConfidence: high` and only include findings with direct exploit evidence. Vendored/generated code examples are scanned but not reported as default exploitable code or PII findings; vulnerable dependency versions are handled through dependency manifests and lockfiles. Use `--min-confidence medium` when you want audit-style review signals such as install scripts, mutable build references, sensitive file paths, broad dependency ranges, or routes without obvious auth middleware.

VibeGuard does not call a remote service in this version.

Optional dependency vulnerability lookup is off by default. LLM03 supply-chain findings require a vulnerable package/version match from a provider such as OSV. `--vuln-provider osv` sends package names and versions to OSV, but never uploads source code.

Enterprise AI inventory and graphing:

- [`docs/ai-bom.md`](./docs/ai-bom.md)
- [`docs/agent-capability-graph.md`](./docs/agent-capability-graph.md)
- [`docs/enterprise-readiness.md`](./docs/enterprise-readiness.md)

Release readiness requires a clean VibeGuard self-scan under the repository `vibeguard.yml` policy.

## Reports

Output formats:

- `table`: terminal security brief with merge decision, business risk, severity mix, priority actions, control gaps, evidence, and follow-up guidance when no findings are generated.
- `json`: automation-friendly report with OWASP summary, warnings, scan metadata, recommendations, evidence, attack path, and impact.
- `sarif`: code-scanning compatible report with invocation metadata, OWASP mapping, and recommendations.
- `markdown`: pull request or review summary grouped by OWASP LLM category with vulnerability narratives.
- `html`: standalone human-readable report with summary cards, OWASP mapping, recommended next actions, evidence, attack path, impact, and fixes.
- `risk-json`: GRC-oriented risk evidence with risk categories, framework mappings, control gaps, technical evidence, AI BOM, and agent graph context.
- `aibom-json` / `aibom-markdown`: AI asset inventory.
- `graph-json` / `graph-markdown`: agent capability graph and high-risk paths.

Useful scan controls:

```bash
vibeguard check --quiet
vibeguard check --max-findings 50
vibeguard check --min-confidence high
vibeguard check --no-color
vibeguard report --format markdown --output vibeguard-report.md
```

Baseline and triage workflow:

```bash
vibeguard baseline --output vibeguard-baseline.json
vibeguard check --baseline vibeguard-baseline.json
vibeguard suppress <finding_id_or_rule_id> --file src/app.js --reason "Reviewed and accepted"
```

The baseline records the current finding IDs so future scans can focus on newly introduced risk. Suppressions are written to `vibeguard.yml` and should include a reason.

Framework-aware checks currently include Express, Next.js, Prisma, Supabase service role usage, Firebase rules, Django CSRF exemptions, and Flask routes without obvious authentication guards.

OWASP references are based on the OWASP Top 10 for LLM Applications 2025 taxonomy from the OWASP GenAI Security Project.

## Configuration

Create a default policy:

```bash
vibeguard init
```

See [`vibeguard.yml.example`](./vibeguard.yml.example) and [`docs/configuration.md`](./docs/configuration.md).

## GitHub Action

After this repository is tagged, use the composite action from a workflow:

```yaml
permissions:
  contents: read
  security-events: write

steps:
  - uses: actions/checkout@v6
  - id: vibeguard
    uses: OWNER/vibeguard@v0.1.0
    with:
      path: "."
      version: "latest"
  - uses: github/codeql-action/upload-sarif@v4
    with:
      sarif_file: ${{ steps.vibeguard.outputs.sarif-file }}
      category: vibeguard
  - name: Fail on blocking findings
    if: steps.vibeguard.outputs.exit-code == '1'
    run: exit 1
```

See [`docs/ci.md`](./docs/ci.md) for CI usage and [`.github/workflows/vibeguard-code-scanning.yml`](./.github/workflows/vibeguard-code-scanning.yml) for this repository's own scan workflow.

## Contributing

Contributions are welcome. Read [`CONTRIBUTING.md`](./CONTRIBUTING.md) for setup, verification, and pull request guidance. For release steps, see [`docs/releasing.md`](./docs/releasing.md).

## Security

Do not open public issues for suspected vulnerabilities. Use the private reporting process in [`SECURITY.md`](./SECURITY.md).
