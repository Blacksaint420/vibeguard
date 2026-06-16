import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseUnifiedDiff, getChangedLineSet } from "../packages/core/src/diff.ts";
import { runCheck } from "../packages/core/src/engine.ts";
import { defaultPolicy } from "../packages/core/src/policy.ts";

test("parseUnifiedDiff extracts added lines and line numbers", () => {
  const diff = [
    "diff --git a/src/app.js b/src/app.js",
    "index abc1234..def5678 100644",
    "--- a/src/app.js",
    "+++ b/src/app.js",
    "@@ -9,0 +10,2 @@",
    "+const sql = `SELECT * FROM users WHERE id = ${req.query.id}`;",
    "+eval(req.body.code);"
  ].join("\n");

  const files = parseUnifiedDiff(diff);

  assert.equal(files.length, 1);
  assert.equal(files[0].path, "src/app.js");
  assert.deepEqual(files[0].addedLines.map((line) => line.line), [10, 11]);
  assert.equal(files[0].addedLines[1].content, "eval(req.body.code);");
});

test("parseUnifiedDiff tracks removed lines for downgrade checks", () => {
  const diff = [
    "diff --git a/requirements.txt b/requirements.txt",
    "index abc1234..def5678 100644",
    "--- a/requirements.txt",
    "+++ b/requirements.txt",
    "@@ -1 +1 @@",
    "-django==5.0.0",
    "+django==3.2.0"
  ].join("\n");

  const files = parseUnifiedDiff(diff);

  assert.equal(files[0].removedLines[0].content, "django==5.0.0");
  assert.equal(files[0].addedLines[0].content, "django==3.2.0");
});

test("getChangedLineSet returns only added line numbers for a file", () => {
  const files = parseUnifiedDiff([
    "diff --git a/src/a.ts b/src/a.ts",
    "--- a/src/a.ts",
    "+++ b/src/a.ts",
    "@@ -1 +1,2 @@",
    "-safe();",
    "+safe();",
    "+dangerous();"
  ].join("\n"));

  const changed = getChangedLineSet(files[0]);

  assert.equal(changed.has(1), true);
  assert.equal(changed.has(2), true);
  assert.equal(changed.has(3), false);
});

test("runCheck enriches diff files with full file context before AI scanning", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-diff-context-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "commented-agent.ts"), [
    "/*",
    'tools: [{ name: "run_shell", execute: () => exec(command) }]',
    "*/",
    ""
  ].join("\n"));

  const diff = [
    "diff --git a/src/commented-agent.ts b/src/commented-agent.ts",
    "index abc1234..def5678 100644",
    "--- a/src/commented-agent.ts",
    "+++ b/src/commented-agent.ts",
    "@@ -1,0 +2 @@",
    '+tools: [{ name: "run_shell", execute: () => exec(command) }]'
  ].join("\n");

  const result = await runCheck({ cwd: root, diffText: diff, policy: defaultPolicy() });

  assert.equal(result.files[0].allLines?.length, 3);
  assert.equal(result.findings.some((finding) => finding.ruleId === "ai-agent-shell-tool-no-approval"), false);
});

test("runCheck uses HEAD context for base diff scans even when the working tree is dirty", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-base-context-"));
  mkdirSync(join(root, "src"), { recursive: true });
  runGit(root, ["init"]);
  runGit(root, ["config", "user.email", "test@example.com"]);
  runGit(root, ["config", "user.name", "Test User"]);

  writeFileSync(join(root, "src", "commented-agent.ts"), "export const ready = true;\n");
  runGit(root, ["add", "src/commented-agent.ts"]);
  runGit(root, ["commit", "-m", "base"]);

  writeFileSync(join(root, "src", "commented-agent.ts"), [
    "/*",
    'tools: [{ name: "run_shell", execute: () => exec(command) }]',
    "*/",
    ""
  ].join("\n"));
  runGit(root, ["add", "src/commented-agent.ts"]);
  runGit(root, ["commit", "-m", "head"]);

  writeFileSync(join(root, "src", "commented-agent.ts"), [
    "const active = true;",
    'tools: [{ name: "run_shell", execute: () => exec(command) }]',
    ""
  ].join("\n"));

  const result = await runCheck({ cwd: root, base: "HEAD~1", policy: defaultPolicy() });

  assert.equal(result.files[0].allLines?.[0]?.content, "/*");
  assert.equal(result.findings.some((finding) => finding.ruleId === "ai-agent-shell-tool-no-approval"), false);
});

function runGit(cwd: string, args: string[]): void {
  const result = spawnSync("git", args, {
    cwd,
    encoding: "utf8"
  });

  assert.equal(result.status, 0, result.stderr || result.stdout);
}
