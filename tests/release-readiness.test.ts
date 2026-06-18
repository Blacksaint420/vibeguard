import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

import { runCli } from "./../packages/cli/src/cli.ts";

test("AI BOM and graph schemas exist", () => {
  const bom = JSON.parse(readFileSync("schemas/vibeguard-aibom.schema.json", "utf8"));
  const graph = JSON.parse(readFileSync("schemas/vibeguard-agent-graph.schema.json", "utf8"));

  assert.equal(bom.properties.schemaVersion.const, "vibeguard.aibom.v1");
  assert.equal(graph.properties.schemaVersion.const, "vibeguard.agentGraph.v1");
});

test("agentic strict policy is shipped", () => {
  const policy = readFileSync("examples/policies/vibeguard-agentic-strict.yml", "utf8");

  assert.equal(policy.includes("mode: block"), true);
  assert.equal(policy.includes("minConfidence: medium"), true);
  assert.equal(policy.includes("requireReviewer: true"), true);
});

test("release governance basics exist", () => {
  for (const file of ["LICENSE", "SECURITY.md", "CHANGELOG.md", "CONTRIBUTING.md", "CODE_OF_CONDUCT.md", "SUPPORT.md"]) {
    assert.equal(existsSync(file), true, `${file} should exist before public release`);
  }
});

test("public collaboration templates exist", () => {
  for (const file of [
    ".github/ISSUE_TEMPLATE/bug_report.yml",
    ".github/ISSUE_TEMPLATE/feature_request.yml",
    ".github/ISSUE_TEMPLATE/config.yml",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/dependabot.yml",
    "docs/releasing.md"
  ]) {
    assert.equal(existsSync(file), true, `${file} should exist before public release`);
  }
});

test("package metadata supports public enterprise adoption", () => {
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));

  assert.equal(pkg.license, "Apache-2.0");
  assert.equal(pkg.repository.url, "git+https://github.com/OWNER/vibeguard.git");
  assert.equal(pkg.publishConfig.provenance, true);
  assert.equal(pkg.keywords.includes("ai-security"), true);
  assert.equal(pkg.keywords.includes("aibom"), true);
});

test("GitHub workflows and action exist", () => {
  for (const file of [
    ".github/workflows/ci.yml",
    ".github/workflows/vibeguard-code-scanning.yml",
    ".github/workflows/release.yml",
    "action.yml"
  ]) {
    assert.equal(existsSync(file), true, `${file} should exist`);
  }

  const release = readFileSync(".github/workflows/release.yml", "utf8");
  assert.equal(release.includes("id-token: write"), true);
  assert.equal(release.includes("npm publish --provenance --access public"), true);

  const scan = readFileSync(".github/workflows/vibeguard-code-scanning.yml", "utf8");
  assert.equal(scan.includes("security-events: write"), true);
  assert.equal(scan.includes("github/codeql-action/upload-sarif"), true);

  const action = readFileSync("action.yml", "utf8");
  assert.equal(action.includes("fail-on-findings"), true);
  assert.equal(action.includes("exit-code"), true);
  assert.equal(action.includes("steps.scan.outputs.status"), true);
});

test("repository has an active self-scan policy", () => {
  assert.equal(existsSync("vibeguard.yml"), true);
  const policy = readFileSync("vibeguard.yml", "utf8");

  assert.equal(policy.includes("enabledScanners:"), true);
  assert.equal(policy.includes("  - ai"), true);
  assert.equal(policy.includes("exclude:"), true);
  assert.equal(policy.includes("tests/**"), true);
  assert.equal(policy.includes("docs/superpowers/**"), true);
  assert.equal(policy.includes("dist/**"), true);
});

test("published package includes enterprise policy examples", () => {
  const pkg = JSON.parse(readFileSync("package.json", "utf8"));

  assert.equal(pkg.files.includes("examples/policies"), true);
  assert.equal(pkg.files.includes("CONTRIBUTING.md"), true);
  assert.equal(pkg.files.includes("docs/releasing.md"), true);
});

test("generated local artifacts are ignored", () => {
  const ignore = readFileSync(".gitignore", "utf8");

  for (const pattern of ["reports/", "*.sarif", "*.tgz", ".env", "vibeguard-aibom.json", "vibeguard-agent-graph.json"]) {
    assert.equal(ignore.includes(pattern), true, `${pattern} should be ignored before public release`);
  }
});

test("repository self-scan has no blocking findings", async () => {
  const writes: string[] = [];
  const result = await runCli(["check", "--quiet", "--format", "json"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(writes.join(""));

  assert.equal(result.exitCode, 0, JSON.stringify(report.summary));
  assert.equal(report.summary.blocking, 0);
});
