# VibeGuard

VibeGuard is a local-first CLI safety check for developers using AI coding agents.

> Check the code your AI just changed before you accept, commit, or merge it.

The first version scans the current git diff and reports high-confidence insecure code, secrets, risky dependency changes, Dockerfile risks, GitHub Actions risks, and sensitive file changes. It does not upload source code.

## Install Locally

```bash
npm install
npm link
```

This project uses Node 25+ and no runtime dependencies.

## Commands

```bash
vibeguard init
vibeguard check
vibeguard check --staged
vibeguard check --base origin/main
vibeguard check --format table
vibeguard check --format json
vibeguard check --format sarif
vibeguard check --format markdown
vibeguard explain js-eval
vibeguard doctor
```

Exit codes:

- `0`: no blocking findings
- `1`: blocking findings found
- `2`: tool, config, or runtime error

## What It Scans

- JavaScript, TypeScript, and Python changed lines for insecure code patterns.
- Added or changed secrets with masking.
- npm, yarn, pnpm, `requirements.txt`, and `pyproject.toml` dependency changes.
- Dockerfile base image risks.
- GitHub Actions mutable references and broad permissions.
- Sensitive file path changes such as `.env`, `.npmrc`, private keys, and cloud credentials.

VibeGuard scans the local git diff only. It does not call a remote service in this version.

## Configuration

Create a default policy:

```bash
vibeguard init
```

See [`vibeguard.yml.example`](./vibeguard.yml.example) and [`docs/configuration.md`](./docs/configuration.md).

