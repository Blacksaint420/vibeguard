import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";

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
  for (const file of ["LICENSE", "SECURITY.md", "CHANGELOG.md"]) {
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
});
