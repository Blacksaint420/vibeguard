import test from "node:test";
import assert from "node:assert/strict";

import { parseUnifiedDiff, getChangedLineSet } from "../packages/core/src/diff.ts";

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
