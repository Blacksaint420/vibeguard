# VibeGuard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the first production-minded VibeGuard TypeScript/npm CLI vertical slice.

**Architecture:** A lean npm workspace monorepo separates CLI, core orchestration, scanners, and output formatters. The check engine consumes local git diffs, runs offline scanners against changed files and added lines, applies policy, and returns unified findings.

**Tech Stack:** Node 25+, npm workspaces, TypeScript syntax executed by Node's built-in type stripping, Node's built-in test runner, no required runtime dependencies.

---

## File Structure

- `package.json`: root npm metadata, scripts, bin entry.
- `.gitignore`: ignored generated files.
- `vibeguard.yml.example`: default policy template.
- `packages/cli/src/index.ts`: executable CLI entrypoint.
- `packages/cli/src/cli.ts`: command parsing and command execution.
- `packages/core/src/types.ts`: shared domain types.
- `packages/core/src/diff.ts`: git diff collection and unified diff parsing.
- `packages/core/src/policy.ts`: config loading, default policy, suppression, blocking decisions.
- `packages/core/src/engine.ts`: scan orchestration.
- `packages/core/src/explain.ts`: rule explanation registry.
- `packages/core/src/prompts.ts`: AI fix prompt generation.
- `packages/scanners/src/code.ts`: JS/TS/Python insecure-code changed-line rules.
- `packages/scanners/src/secrets.ts`: secret detection and masking.
- `packages/scanners/src/dependencies.ts`: dependency manifest and lockfile checks.
- `packages/scanners/src/docker.ts`: Dockerfile checks.
- `packages/scanners/src/actions.ts`: GitHub Actions workflow checks.
- `packages/scanners/src/sensitive-files.ts`: sensitive file path checks.
- `packages/scanners/src/index.ts`: scanner registry.
- `packages/output/src/formatters.ts`: table, JSON, SARIF, and Markdown output.
- `tests/*.test.ts`: behavior tests for parser, scanners, policy, output, engine, and CLI.
- `examples/vulnerable-js-app/*`: small JavaScript fixture.
- `examples/vulnerable-python-app/*`: small Python fixture.
- `docs/*.md`: concise user docs.

## Tasks

### Task 1: Scaffolding and Failing Tests

**Files:**
- Create: `package.json`
- Create: `.gitignore`
- Create: `tests/diff.test.ts`
- Create: `tests/scanners.test.ts`
- Create: `tests/policy-output.test.ts`
- Create: `tests/cli.test.ts`

- [x] **Step 1: Write package scripts and failing behavior tests**

Use Node's built-in test runner with TypeScript test files. Tests should import the intended public modules before those modules exist.

- [ ] **Step 2: Run tests to verify failure**

Run: `npm test`

Expected: FAIL with module-not-found errors for `packages/core`, `packages/scanners`, `packages/output`, or `packages/cli`.

### Task 2: Core Types, Diff Parser, Policy, and Output

**Files:**
- Create: `packages/core/src/types.ts`
- Create: `packages/core/src/diff.ts`
- Create: `packages/core/src/policy.ts`
- Create: `packages/core/src/prompts.ts`
- Create: `packages/core/src/explain.ts`
- Create: `packages/output/src/formatters.ts`

- [ ] **Step 1: Implement the smallest core contracts needed by tests**

Define findings, parsed diffs, scanners, policies, and output formatters.

- [ ] **Step 2: Run targeted tests**

Run: `node --test tests/diff.test.ts tests/policy-output.test.ts`

Expected: PASS.

### Task 3: Scanner Implementations

**Files:**
- Create: `packages/scanners/src/code.ts`
- Create: `packages/scanners/src/secrets.ts`
- Create: `packages/scanners/src/dependencies.ts`
- Create: `packages/scanners/src/docker.ts`
- Create: `packages/scanners/src/actions.ts`
- Create: `packages/scanners/src/sensitive-files.ts`
- Create: `packages/scanners/src/index.ts`

- [ ] **Step 1: Implement high-confidence changed-line scanners**

Each scanner returns normalized findings with rule metadata and masked snippets.

- [ ] **Step 2: Run scanner tests**

Run: `node --test tests/scanners.test.ts`

Expected: PASS.

### Task 4: Engine and CLI

**Files:**
- Create: `packages/core/src/engine.ts`
- Create: `packages/cli/src/cli.ts`
- Create: `packages/cli/src/index.ts`

- [ ] **Step 1: Implement scan orchestration and CLI commands**

Support `init`, `check`, `check --staged`, `check --base`, `check --format`, `explain`, and `doctor`.

- [ ] **Step 2: Run CLI tests**

Run: `node --test tests/cli.test.ts`

Expected: PASS.

### Task 5: Docs, Examples, and Final Verification

**Files:**
- Create: `README.md`
- Create: `docs/getting-started.md`
- Create: `docs/configuration.md`
- Create: `docs/pre-commit.md`
- Create: `docs/ci.md`
- Create: `docs/rules.md`
- Create: `docs/dependency-security.md`
- Create: `docs/security-model.md`
- Create: `vibeguard.yml.example`
- Create: `examples/vulnerable-js-app/package.json`
- Create: `examples/vulnerable-js-app/src/app.js`
- Create: `examples/vulnerable-python-app/requirements.txt`
- Create: `examples/vulnerable-python-app/app.py`

- [ ] **Step 1: Add concise docs and vulnerable examples**

Docs must match implemented behavior and state that VibeGuard does not upload source code.

- [ ] **Step 2: Run full verification**

Run: `npm test`

Expected: PASS.

Run: `npm run vibeguard -- doctor`

Expected: exit `0` and local environment summary.

Run: `npm run vibeguard -- check --format json`

Expected: valid JSON report and no runtime error.
