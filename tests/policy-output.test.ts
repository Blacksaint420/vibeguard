import test from "node:test";
import assert from "node:assert/strict";

import { applyPolicy, defaultPolicy, loadPolicyFromText } from "../packages/core/src/policy.ts";
import { runCheckFromDiff } from "../packages/core/src/engine.ts";
import { createFindingId } from "../packages/core/src/types.ts";
import { renderJson, renderMarkdown, renderSarif, renderTable } from "../packages/output/src/formatters.ts";

function finding(overrides = {}) {
  const base = {
    id: "",
    ruleId: "js-eval",
    title: "eval usage",
    severity: "high",
    confidence: "high",
    riskScore: 90,
    file: "src/app.js",
    line: 3,
    snippet: "eval(req.body.code)",
    why: "Dynamic code execution can run attacker-controlled input.",
    suggestedFix: "Replace eval with a safe parser or explicit dispatch.",
    aiFixPrompt: "Replace eval safely and add tests.",
    testSuggestion: "Add a test with untrusted input.",
    blocking: false
  };
  return { ...base, ...overrides };
}

test("applyPolicy marks high severity findings as blocking by default", () => {
  const [result] = applyPolicy([finding()], defaultPolicy());

  assert.equal(result.blocking, true);
});

test("applyPolicy honors rule suppressions", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 0);
});

test("createFindingId is stable for the same rule and location", () => {
  assert.equal(
    createFindingId("js-eval", "src/app.js", 3, "eval(req.body.code)"),
    createFindingId("js-eval", "src/app.js", 3, "eval(req.body.code)")
  );
});

test("formatters render table, JSON, SARIF, and Markdown", () => {
  const findings = applyPolicy([finding()], defaultPolicy());
  const json = JSON.parse(renderJson(findings));
  const sarif = JSON.parse(renderSarif(findings));
  const table = renderTable(findings);
  const markdown = renderMarkdown(findings);

  assert.equal(json.findings[0].ruleId, "js-eval");
  assert.equal(sarif.version, "2.1.0");
  assert.equal(sarif.runs[0].results[0].ruleId, "js-eval");
  assert.equal(table.includes("js-eval"), true);
  assert.equal(markdown.includes("## VibeGuard Security Summary"), true);
});

test("runCheck enriches findings with enterprise context before rendering", async () => {
  const diff = [
    "diff --git a/src/app.js b/src/app.js",
    "index 0000000..abc1234 100644",
    "--- a/src/app.js",
    "+++ b/src/app.js",
    "@@ -0,0 +1 @@",
    "+eval(req.body.code);"
  ].join("\n");

  const report = await runCheckFromDiff(diff);

  assert.equal(report.findings[0].rule?.version, "2026.06.11");
  assert.equal(report.findings[0].frameworks?.some((entry) => entry.framework === "owasp-llm-2025"), true);
  assert.equal(report.findings[0].risk?.category, "AI application security");
  assert.equal(report.findings[0].snippet, "eval(req.body.code);");
});
