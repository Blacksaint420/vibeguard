import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { collectRepositoryFiles } from "../packages/core/src/repository.ts";
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
