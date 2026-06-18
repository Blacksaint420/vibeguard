# Contributing to VibeGuard

Thanks for helping improve VibeGuard. This project is pre-1.0, so contributors should expect rule behavior, report fields, and CLI ergonomics to evolve while the core local-first security model stays stable.

## Development Setup

Requirements:

- Node.js 20 or newer
- npm

Install and build:

```bash
npm install
npm run build
```

Run the CLI from source:

```bash
npm run vibeguard -- doctor
npm run vibeguard -- check --quiet
```

Run the compiled CLI:

```bash
npm run vibeguard:dist -- doctor
```

## Verification

Before opening a pull request, run:

```bash
npm test
npm run build
npm pack --dry-run
```

For scanner, rules, formatter, or policy changes, also run a local self-scan:

```bash
npm run vibeguard:dist -- check --quiet --format json
```

Do not commit generated reports, package tarballs, local baselines, `.env` files, or `dist/`.

## Pull Requests

Good pull requests include:

- A short explanation of the security or developer workflow being improved.
- Focused tests for changed rules, scanners, output formats, or CLI behavior.
- Updated docs when commands, config, output fields, or rule behavior changes.
- Notes about compatibility impact if rule IDs, schema fields, or exit codes change.

Keep changes scoped. Large refactors are easier to review when they are separated from behavior changes.

## Security Changes

VibeGuard intentionally avoids source-code upload by default. Changes that add network access, new report fields, additional file collection, or dependency vulnerability lookup behavior must document:

- What data leaves the local machine.
- Whether the behavior is opt-in or default.
- How secrets and sensitive source snippets are masked.
- How users can disable or configure the behavior.

Report vulnerabilities privately through the process in `SECURITY.md`.
