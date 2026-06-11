import test from "node:test";
import assert from "node:assert/strict";

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

test("parseArgs supports repository path for full scan", () => {
  const command = parseArgs(["check", "/tmp/CV Maker", "--format", "json"]);

  assert.equal(command.name, "check");
  assert.equal(command.targetPath, "/tmp/CV Maker");
  assert.equal(command.staged, false);
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
