import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { collectRepository, collectRepositoryFiles } from "../packages/core/src/repository.ts";
import { runCheck } from "../packages/core/src/engine.ts";
import { defaultPolicy } from "../packages/core/src/policy.ts";

test("collectRepositoryFiles includes all directories by default", () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-repo-"));
  mkdirSync(join(root, ".git", "hooks"), { recursive: true });
  mkdirSync(join(root, "node_modules", "bad-package"), { recursive: true });
  mkdirSync(join(root, "dist"), { recursive: true });
  mkdirSync(join(root, ".next"), { recursive: true });
  mkdirSync(join(root, ".venv"), { recursive: true });
  writeFileSync(join(root, ".git", "hooks", "post-checkout"), "eval(req.body.code);\n");
  writeFileSync(join(root, "node_modules", "bad-package", "index.js"), "eval(req.body.code);\n");
  writeFileSync(join(root, "dist", "bundle.js"), "eval(req.body.code);\n");
  writeFileSync(join(root, ".next", "server.js"), "eval(req.body.code);\n");
  writeFileSync(join(root, ".venv", "bad.py"), "requests.get(url, verify=False)\n");

  const files = collectRepositoryFiles(root);
  const paths = files.map((file) => file.path).sort();

  assert.deepEqual(paths, [
    ".git/hooks/post-checkout",
    ".next/server.js",
    ".venv/bad.py",
    "dist/bundle.js",
    "node_modules/bad-package/index.js"
  ]);
});

test("runCheck scans full repository when no diff mode is selected", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-full-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "eval(req.body.code);\n");

  const result = await runCheck({ cwd: root, policy: defaultPolicy() });

  assert.equal(result.files.length, 1);
  assert.equal(result.findings[0].ruleId, "js-eval");
  assert.equal(result.findings[0].blocking, true);
});

test("collectRepositoryFiles follows symlinked directories without reading them as files", () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-symlink-"));
  mkdirSync(join(root, "packages", "app"), { recursive: true });
  mkdirSync(join(root, "node_modules"), { recursive: true });
  writeFileSync(join(root, "packages", "app", "index.js"), "eval(req.body.code);\n");
  symlinkSync(join(root, "packages", "app"), join(root, "node_modules", "app"), "dir");

  const files = collectRepositoryFiles(root);
  const paths = files.map((file) => file.path).sort();

  assert.deepEqual(paths, [
    "node_modules/app/index.js",
    "packages/app/index.js"
  ]);
});

test("collectRepository skips symlinks that resolve outside the target root", () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-symlink-root-"));
  const outside = mkdtempSync(join(tmpdir(), "vibeguard-symlink-outside-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "eval(req.body.code);\n");
  writeFileSync(join(outside, "secret.js"), "eval(secret);\n");
  symlinkSync(outside, join(root, "outside"), "dir");

  const result = collectRepository(root);
  const paths = result.files.map((file) => file.path).sort();

  assert.deepEqual(paths, ["src/app.js"]);
  assert.equal(result.warnings.some((warning) => warning.path === "outside" && warning.message.includes("outside target root")), true);
});

test("collectRepository skips binary and oversized files", () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-file-limits-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "eval(req.body.code);\n");
  writeFileSync(join(root, "src", "binary.dat"), Buffer.from([0x41, 0x00, 0x42]));
  writeFileSync(join(root, "src", "large.txt"), "x".repeat(1024 * 1024 + 1));

  const result = collectRepository(root);
  const paths = result.files.map((file) => file.path).sort();

  assert.deepEqual(paths, ["src/app.js"]);
  assert.equal(result.warnings.some((warning) => warning.path === "src/binary.dat" && warning.message.includes("binary")), true);
  assert.equal(result.warnings.some((warning) => warning.path === "src/large.txt" && warning.message.includes("larger")), true);
});

test("collectRepository reports structured coverage for skipped files", () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-coverage-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "ok\n");
  writeFileSync(join(root, "src", "binary.dat"), Buffer.from([0x41, 0x00, 0x42]));
  writeFileSync(join(root, "src", "large.txt"), "x".repeat(20));

  const result = collectRepository(root, { maxFileBytes: 10 });

  assert.equal(result.coverage.filesDiscovered, 3);
  assert.equal(result.coverage.filesScanned, 1);
  assert.equal(result.coverage.filesSkippedBinary, 1);
  assert.equal(result.coverage.filesSkippedOversized, 1);
  assert.equal(result.coverage.coverageStatus, "partial");
  assert.equal(result.warnings.some((warning) => warning.code === "binary"), true);
  assert.equal(result.warnings.some((warning) => warning.code === "oversized"), true);
});

test("collectRepository reports file limit coverage", () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-file-limit-"));
  writeFileSync(join(root, "a.js"), "ok\n");
  writeFileSync(join(root, "b.js"), "ok\n");

  const result = collectRepository(root, { maxFiles: 1 });

  assert.equal(result.files.length, 1);
  assert.equal(result.coverage.fileLimitReached, true);
  assert.equal(result.coverage.coverageStatus, "partial");
  assert.equal(result.warnings.some((warning) => warning.code === "file-limit"), true);
});

test("runCheck reports files excluded by policy in coverage", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-policy-coverage-"));
  mkdirSync(join(root, "src"), { recursive: true });
  mkdirSync(join(root, "ignored"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "const ok = true;\n");
  writeFileSync(join(root, "ignored", "app.js"), "eval(req.body.code);\n");

  const policy = { ...defaultPolicy(), exclude: ["ignored/**"] };
  const result = await runCheck({ cwd: root, policy });

  assert.equal(result.coverage.filesDiscovered, 2);
  assert.equal(result.coverage.filesScanned, 1);
  assert.equal(result.coverage.filesExcludedByPolicy, 1);
  assert.equal(result.coverage.coverageStatus, "partial");
});
