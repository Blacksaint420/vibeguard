import test from "node:test";
import assert from "node:assert/strict";

import { applyPolicy, defaultPolicy, loadPolicyFromText } from "../packages/core/src/policy.ts";
import { runCheckFromDiff } from "../packages/core/src/engine.ts";
import { createFindingId } from "../packages/core/src/types.ts";
import { renderFindings, renderJson, renderMarkdown, renderRiskJson, renderSarif, renderTable } from "../packages/output/src/formatters.ts";

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

test("explicit enabledScanners config replaces defaults", () => {
  assert.equal(defaultPolicy().enabledScanners.includes("ai"), true);

  const policy = loadPolicyFromText([
    "enabledScanners:",
    "  - code",
    "  - secrets"
  ].join("\n"));

  assert.deepEqual(policy.enabledScanners, ["code", "secrets"]);
  assert.equal(policy.enabledScanners.includes("ai"), false);
});

test("applyPolicy honors rule suppressions", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressionPolicy:",
    "  requireReason: false",
    "  requireReviewer: false",
    "  requireExpiration: false",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 0);
});

test("legacy configs without suppression policy honor old suppressions", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 0);
});

test("enterprise suppressions require reason, reviewer, and unexpired date", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressionPolicy:",
    "  requireReason: true",
    "  requireReviewer: true",
    "  requireExpiration: true",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js",
    "    reason: accepted for migration",
    "    reviewer: security@example.com",
    "    expires: 2099-01-01"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 0);
});

test("expired suppressions do not hide findings", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressionPolicy:",
    "  requireReason: true",
    "  requireReviewer: true",
    "  requireExpiration: true",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js",
    "    reason: accepted for migration",
    "    reviewer: security@example.com",
    "    expires: 2020-01-01"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 1);
  assert.equal(results[0].blocking, true);
});

test("suppressions missing required reviewer do not hide findings", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressionPolicy:",
    "  requireReason: true",
    "  requireReviewer: true",
    "  requireExpiration: true",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js",
    "    reason: accepted for migration",
    "    expires: 2099-01-01"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 1);
  assert.equal(results[0].blocking, true);
});

test("suppressions missing required reason do not hide findings", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressionPolicy:",
    "  requireReason: true",
    "  requireReviewer: true",
    "  requireExpiration: true",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js",
    "    reviewer: security@example.com",
    "    expires: 2099-01-01"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 1);
  assert.equal(results[0].blocking, true);
});

test("suppressions missing required expiration do not hide findings", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressionPolicy:",
    "  requireReason: true",
    "  requireReviewer: true",
    "  requireExpiration: true",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js",
    "    reason: accepted for migration",
    "    reviewer: security@example.com"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 1);
  assert.equal(results[0].blocking, true);
});

test("malformed suppression expiration does not hide findings", () => {
  const policy = loadPolicyFromText([
    "mode: block",
    "suppressionPolicy:",
    "  requireReason: true",
    "  requireReviewer: true",
    "  requireExpiration: true",
    "suppressions:",
    "  - rule: js-eval",
    "    file: src/app.js",
    "    reason: accepted for migration",
    "    reviewer: security@example.com",
    "    expires: 2099-02-30"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 1);
  assert.equal(results[0].blocking, true);
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

test("renderRiskJson emits GRC risk report with technical evidence", () => {
  const findings = applyPolicy([
    finding({
      title: "JavaScript eval usage",
      snippet: "eval(req.body.code)",
      evidence: "The code executes a string dynamically with eval.",
      rule: {
        id: "js-eval",
        name: "JavaScript eval",
        version: "2026.06.11",
        stability: "stable",
        scanner: "code"
      },
      frameworks: [
        {
          framework: "owasp-llm-2025",
          id: "LLM05:2025",
          name: "Improper Output Handling",
          sourceVersion: "2025"
        }
      ],
      risk: {
        category: "AI application security",
        likelihood: "high",
        impact: "high",
        severity: "high",
        controlOwner: "engineering"
      },
      controlGaps: ["Unsafe dynamic code execution"]
    })
  ], defaultPolicy());

  const report = JSON.parse(renderRiskJson(findings));

  assert.equal(report.tool, "vibeguard");
  assert.equal(report.reportType, "grc-risk");
  assert.equal(report.riskSummary.totalFindings, 1);
  assert.equal(report.risks[0].technicalEvidence[0].ruleId, "js-eval");
  assert.equal(report.risks[0].technicalEvidence[0].file, "src/app.js");
  assert.equal(report.risks[0].technicalEvidence[0].line, 3);
  assert.equal(report.risks[0].technicalEvidence[0].title, "JavaScript eval usage");
  assert.equal(report.risks[0].technicalEvidence[0].snippet, "eval(req.body.code)");
  assert.equal(report.risks[0].technicalEvidence[0].evidence, "The code executes a string dynamically with eval.");
});

test("renderRiskJson summarizes unmapped findings consistently", () => {
  const report = JSON.parse(renderRiskJson([finding()]));

  assert.deepEqual(report.riskSummary.byCategory, [
    { category: "Unmapped technical finding", count: 1, highestSeverity: "high" }
  ]);
  assert.equal(report.risks[0].category, "Unmapped technical finding");
  assert.equal(report.risks[0].technicalEvidence[0].ruleId, "js-eval");
});

test("renderFindings dispatches risk-json format", () => {
  const direct = JSON.parse(renderRiskJson([finding()]));
  const dispatched = JSON.parse(renderFindings([finding()], "risk-json"));

  assert.equal(dispatched.reportType, "grc-risk");
  assert.deepEqual(dispatched.riskSummary, direct.riskSummary);
  assert.deepEqual(dispatched.risks, direct.risks);
});

test("renderRiskJson groups category details with unique metadata and highest severity", () => {
  const framework = {
    framework: "nist-ai-rmf",
    id: "MAP-1",
    name: "Map risks",
    sourceVersion: "1.0"
  };
  const findings = [
    finding({
      id: "first",
      severity: "medium",
      frameworks: [framework],
      risk: {
        category: "AI application security",
        likelihood: "medium",
        impact: "medium",
        severity: "medium",
        controlOwner: "security"
      },
      controlGaps: ["Input validation", "Secure code review"]
    }),
    finding({
      id: "second",
      severity: "critical",
      frameworks: [framework],
      risk: {
        category: "AI application security",
        likelihood: "high",
        impact: "critical",
        severity: "critical",
        controlOwner: "security"
      },
      controlGaps: ["Input validation"]
    })
  ];

  const report = JSON.parse(renderRiskJson(findings));
  const [risk] = report.risks;

  assert.equal(risk.category, "AI application security");
  assert.equal(risk.highestSeverity, "critical");
  assert.equal(risk.frameworks.length, 1);
  assert.deepEqual(risk.controlGaps, ["Input validation", "Secure code review"]);
  assert.equal(risk.technicalEvidence.length, 2);
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

test("runCheck includes medium-confidence RAG findings in audit mode", async () => {
  const diff = [
    "diff --git a/src/rag.ts b/src/rag.ts",
    "index 0000000..abc1234 100644",
    "--- a/src/rag.ts",
    "+++ b/src/rag.ts",
    "@@ -0,0 +1 @@",
    "+await vectorStore.similaritySearch(query, 50);"
  ].join("\n");

  const defaultReport = await runCheckFromDiff(diff);
  const auditReport = await runCheckFromDiff(diff, { ...defaultPolicy(), minConfidence: "medium" });

  assert.equal(defaultReport.findings.some((finding) => finding.ruleId === "ai-rag-query-without-filter"), false);
  assert.equal(auditReport.findings.some((finding) => finding.ruleId === "ai-rag-query-without-filter"), true);
});
