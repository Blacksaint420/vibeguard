import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseArgs, runCli } from "../packages/cli/src/cli.ts";

const vulnerableDiff = [
  "diff --git a/src/app.js b/src/app.js",
  "--- a/src/app.js",
  "+++ b/src/app.js",
  "@@ -1,0 +1 @@",
  "+eval(req.body.code);"
].join("\n");

test("parseArgs supports check options", () => {
  const command = parseArgs(["check", "--staged", "--format", "json"]);

  assert.equal(command.name, "check");
  assert.equal(command.staged, true);
  assert.equal(command.format, "json");
});

test("parseArgs supports risk-json output format", () => {
  const command = parseArgs(["check", "--staged", "--format", "risk-json"]);

  assert.equal(command.name, "check");
  assert.equal(command.staged, true);
  assert.equal(command.format, "risk-json");
});

test("parseArgs supports repository path for full scan", () => {
  const command = parseArgs(["check", "/tmp/CV Maker", "--format", "json"]);

  assert.equal(command.name, "check");
  assert.equal(command.targetPath, "/tmp/CV Maker");
  assert.equal(command.staged, false);
});

test("parseArgs supports enterprise suppress options", () => {
  const command = parseArgs([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-01-01"
  ]);

  assert.equal(command.name, "suppress");
  assert.equal(command.id, "js-eval");
  assert.equal(command.file, "src/app.js");
  assert.equal(command.reason, "accepted for migration");
  assert.equal(command.reviewer, "security@example.com");
  assert.equal(command.expires, "2099-01-01");
});

test("runCli rejects suppressions missing required enterprise fields", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const writes: string[] = [];
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration"
  ], {
    cwd,
    stdout: (text) => writes.push(text),
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(writes.join(""), "");
  assert.equal(errors.join("").includes("Missing required suppression fields: reviewer, expires"), true);
  assert.equal(existsSync(join(cwd, "vibeguard.yml")), false);
});

test("runCli rejects suppressions missing required reason", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-01-01"
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("Missing required suppression fields: reason"), true);
  assert.equal(existsSync(join(cwd, "vibeguard.yml")), false);
});

test("runCli rejects malformed suppression expiration", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-02-30"
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("--expires must be a valid YYYY-MM-DD date"), true);
  assert.equal(existsSync(join(cwd, "vibeguard.yml")), false);
});

test("runCli rejects expired suppression expiration", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2020-01-01"
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("--expires must be a future or current YYYY-MM-DD date"), true);
  assert.equal(existsSync(join(cwd, "vibeguard.yml")), false);
});

test("runCli appends legacy suppressions when config has no suppression policy", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const configPath = join(cwd, "vibeguard.yml");
  writeFileSync(configPath, [
    "mode: block",
    "suppressions: []"
  ].join("\n"));

  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js"
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 0);
  assert.equal(errors.join(""), "");
  assert.equal(readFileSync(configPath, "utf8").includes("  - rule: js-eval"), true);
});

test("runCli returns blocking exit code for vulnerable staged diff", async () => {
  const writes: string[] = [];
  const result = await runCli(["check", "--staged", "--format", "json"], {
    cwd: process.cwd(),
    collectDiff: () => vulnerableDiff,
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(writes.join(""));

  assert.equal(result.exitCode, 1);
  assert.equal(report.findings[0].ruleId, "js-eval");
  assert.equal(report.findings[0].blocking, true);
});

test("runCli defaults to full repository scan without diff collection", async () => {
  const writes: string[] = [];
  let diffCalled = false;
  const result = await runCli(["check", "--format", "json"], {
    cwd: process.cwd(),
    collectRepositoryFiles: () => [{
      path: "src/app.js",
      oldPath: "src/app.js",
      status: "modified",
      addedLines: [{ line: 1, content: "eval(req.body.code);" }],
      removedLines: []
    }],
    collectDiff: () => {
      diffCalled = true;
      return vulnerableDiff;
    },
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(writes.join(""));

  assert.equal(diffCalled, false);
  assert.equal(result.exitCode, 1);
  assert.equal(report.findings[0].ruleId, "js-eval");
});

test("runCli explain returns rule details", async () => {
  const writes: string[] = [];
  const result = await runCli(["explain", "js-eval"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  assert.equal(result.exitCode, 0);
  assert.equal(writes.join("").includes("Dynamic code execution"), true);
});

test("runCli explain includes enterprise rule metadata", async () => {
  const writes: string[] = [];
  const result = await runCli(["explain", "js-eval"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const output = writes.join("");

  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("Rule version: 2026.06.11"), true);
  assert.equal(output.includes("Framework mappings:"), true);
  assert.equal(output.includes("OWASP Top 10 for LLM Applications"), true);
});

test("runCli doctor reports local-first behavior", async () => {
  const writes: string[] = [];
  const result = await runCli(["doctor"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  assert.equal(result.exitCode, 0);
  assert.equal(writes.join("").includes("No source upload"), true);
});
