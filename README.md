# VibeGuard

VibeGuard is a local-first CLI safety check for developers using AI coding agents.

> Check the code your AI just changed before you accept, commit, or merge it.

The first version scans the repository you point it at and reports high-confidence code, LLM application, and supply-chain vulnerabilities. Findings are mapped to the OWASP Top 10 for LLM Applications 2025 where applicable, with evidence, attack path, impact, and a concrete fix. It does not upload source code.

## Install Locally

```bash
npm install
npm run build
npm link
```

The published CLI runs from compiled JavaScript in `dist/` and targets Node 20+. The source tests use the local Node runtime.

## Commands

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
- OWASP LLM 2025 risks including prompt injection, sensitive information disclosure, supply chain, improper output handling, excessive agency, system prompt leakage, vector/embedding weaknesses, and unbounded consumption when there is direct code evidence.
- Secrets with masking.
- npm, yarn, pnpm, `requirements.txt`, and `pyproject.toml` dependency manifests.
- Dockerfile base image risks.
- GitHub Actions mutable references and broad permissions.
- Sensitive file path changes such as `.env`, `.npmrc`, private keys, and cloud credentials.

By default, `vibeguard check` walks the full repository, including generated directories, dependency directories, git metadata, large files, and binary-looking files. Use `--staged` or `--base` when you want a focused git-diff scan.

Default reports use `minConfidence: high` to avoid noisy "possible issue" output. Use `--min-confidence medium` when you want audit-style review signals such as broad dependency ranges or routes without obvious auth middleware.

VibeGuard does not call a remote service in this version.

Optional dependency vulnerability lookup is off by default. `--vuln-provider osv` sends package names and versions to OSV, but never uploads source code.

## Reports

Output formats:

- `table`: terminal report focused on OWASP category, impact, location, and fix priority.
- `json`: automation-friendly report with OWASP summary, warnings, scan metadata, recommendations, evidence, attack path, and impact.
- `sarif`: code-scanning compatible report with invocation metadata, OWASP mapping, and recommendations.
- `markdown`: pull request or review summary grouped by OWASP LLM category with vulnerability narratives.
- `html`: standalone human-readable report with summary cards, OWASP mapping, recommended next actions, evidence, attack path, impact, and fixes.

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
