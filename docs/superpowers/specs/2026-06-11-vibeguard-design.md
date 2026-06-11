# VibeGuard Design

## Goal

Build VibeGuard as a local-first TypeScript/npm CLI that checks only the code and dependency changes in the current git diff before a developer accepts, commits, or merges AI-generated code.

Primary promise: "Check the code your AI just changed before you accept, commit, or merge it."

## Scope

The first vertical slice provides a production-minded CLI with modular internals:

- `vibeguard init`
- `vibeguard check`
- `vibeguard check --staged`
- `vibeguard check --base <branch>`
- `vibeguard check --format table|json|sarif|markdown`
- `vibeguard explain <finding_id_or_rule_id>`
- `vibeguard doctor`

The first release is offline by default. It does not upload source code or dependency manifests. Vulnerability lookups are behind a provider interface with null and mock providers, so a future OSV-compatible provider can be added without changing scanner contracts.

## Architecture

Use a lean npm workspace monorepo:

- `packages/cli`: command parsing, process exit codes, terminal I/O.
- `packages/core`: check orchestration, git diff collection, diff parsing, changed-line mapping, policy loading, risk scoring, AI prompt generation.
- `packages/scanners`: code rules, secret scanning, dependency checks, Dockerfile checks, GitHub Actions checks, sensitive file checks.
- `packages/output`: table, JSON, SARIF, and Markdown renderers.
- `examples`: small vulnerable fixtures.
- `docs`: user documentation.

The CLI calls the core engine. The engine collects or receives a git diff, parses it into changed files and changed added lines, runs enabled scanners, normalizes findings, applies policy, and renders the selected output format.

## Data Flow

1. `vibeguard check` resolves options: default unstaged diff, `--staged`, or `--base <branch>`.
2. The git diff collector runs local `git diff` only.
3. The diff parser extracts changed files, added line numbers, added snippets, and removed snippets where available.
4. Scanners run against the parsed diff:
   - Code scanner: JavaScript, TypeScript, and Python changed lines.
   - Secret scanner: all changed lines with masking.
   - Dependency scanner: npm, yarn, pnpm, requirements, and pyproject changes.
   - Dockerfile scanner: changed Dockerfile lines.
   - GitHub Actions scanner: workflow changes.
   - Sensitive file scanner: file path based detection.
5. Findings receive severity, confidence, risk score, masked snippet, explanation, suggested fix, AI fix prompt, test suggestion, and blocking status.
6. Output renderers produce table, JSON, SARIF, or Markdown.
7. Exit code is `1` only when blocking findings are present, `0` when no blocking findings are present, and `2` for tool/config/runtime errors.

## Rule Strategy

The initial rule set favors high-confidence matching over broad heuristics. Noisy rules, such as route auth inference, are included only as lower-confidence warnings unless the evidence is strong.

Implemented rule families:

- JavaScript/TypeScript: eval, Function constructor, SQL template interpolation, dangerous exec with request-derived input, JWT decode without verification, permissive CORS, insecure cookies, TLS verification disabled, SSRF-shaped fetch/axios from request input, path traversal-shaped filesystem access, and `Math.random` token generation.
- Python: SQL f-string or formatting, subprocess with `shell=True` and request/input content, eval/exec, pickle loads, unsafe YAML load, `requests` with `verify=False`, Flask/Django debug mode, weak random token generation, JWT decode verification disabled, and permissive CORS.
- Secrets: private keys, cloud access keys, GitHub tokens, Slack tokens, generic API keys/passwords, authorization headers, and `.env` leaks.
- Dependencies: new or changed dependency lines, broad or unpinned versions, version downgrades when visible in the diff, suspicious package names, lockfile-only changes, Docker base image `latest`, and mutable GitHub Action references.
- GitHub Actions: mutable `uses:` references, `permissions: write-all`, and high-risk trigger patterns.
- Sensitive files: `.env`, private keys, package registry credentials, cloud credential files, kube config, and SSH material.

## Policy

`vibeguard init` writes `vibeguard.yml` with defaults for:

- mode: `block`
- enabled scanners
- include and exclude globs
- dependency policy
- secret policy
- sensitive file policy
- suppression policy
- AI prompt settings

The first parser supports the generated default config and simple project overrides without requiring external YAML dependencies. Suppressions can match rule IDs, file globs, and optional line numbers.

## Outputs

Every finding includes:

- severity
- confidence
- risk score
- file
- line
- masked code snippet
- why it matters
- suggested fix
- AI fix prompt
- test suggestion
- blocking status

SARIF output targets GitHub code scanning compatibility. Markdown output targets pull request summaries. JSON output is stable enough for scripting.

## Testing

Use Node's built-in test runner against TypeScript source. Tests cover:

- git diff parsing
- changed-line filtering
- rule matching
- secret masking
- dependency parsing
- Dockerfile parsing
- GitHub Actions parsing
- risk scoring and policy blocking
- policy loading and suppression
- JSON output
- SARIF output
- CLI exit codes

## Constraints

- No source upload.
- No auto-fix in v1.
- No required runtime network calls.
- Keep the first implementation dependency-light and fast enough for pre-commit use.
- Preserve modular package boundaries even though the first release is small.
