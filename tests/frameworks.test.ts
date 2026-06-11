import test from "node:test";
import assert from "node:assert/strict";

import { createFinding } from "../packages/core/src/types.ts";
import { enrichFindingWithEnterpriseContext } from "../packages/core/src/frameworks/crosswalk.ts";
import { summarizeGrcRisks } from "../packages/core/src/risk.ts";

function technicalFinding(ruleId = "js-eval") {
  return createFinding({
    ruleId,
    title: "JavaScript eval usage",
    severity: "high",
    confidence: "high",
    riskScore: 90,
    file: "src/app.js",
    line: 3,
    snippet: "eval(req.body.code)",
    evidence: "The code executes a string dynamically with eval.",
    attackPath: "Untrusted text reaches eval and executes as JavaScript.",
    impact: "This can execute attacker-controlled code in the application process.",
    why: "Dynamic code execution can run attacker-controlled input.",
    suggestedFix: "Replace eval with a safe parser or explicit dispatch.",
    aiFixPrompt: "Replace eval safely and add tests.",
    testSuggestion: "Add a test with untrusted input."
  });
}

test("enterprise context enriches a technical finding without changing evidence", () => {
  const enriched = enrichFindingWithEnterpriseContext(technicalFinding());

  assert.equal(enriched.rule?.id, "js-eval");
  assert.equal(enriched.rule?.version, "2026.06.11");
  assert.equal(enriched.evidence, "The code executes a string dynamically with eval.");
  assert.equal(enriched.frameworks.some((entry) => entry.framework === "owasp-llm-2025"), true);
  assert.equal(enriched.frameworks.some((entry) => entry.framework === "nist-ai-rmf"), true);
  assert.equal(enriched.frameworks.some((entry) => entry.framework === "mitre-atlas"), true);
  assert.equal(enriched.frameworks.some((entry) => entry.framework === "google-saif"), true);
  assert.equal(enriched.risk?.category, "AI application security");
  assert.equal(enriched.risk?.likelihood, "high");
  assert.equal(enriched.risk?.impact, "high");
  assert.deepEqual(enriched.controlGaps, ["unsafe code execution", "output handling", "least privilege"]);
});

test("unknown rules keep technical findings and receive default risk context", () => {
  const enriched = enrichFindingWithEnterpriseContext(technicalFinding("custom-rule"));

  assert.equal(enriched.rule?.id, "custom-rule");
  assert.equal(enriched.rule?.stability, "custom");
  assert.equal(enriched.frameworks.length, 0);
  assert.equal(enriched.risk?.category, "Unmapped technical finding");
});

test("GRC risk summary groups enriched findings by category and framework", () => {
  const findings = [
    enrichFindingWithEnterpriseContext(technicalFinding("js-eval")),
    enrichFindingWithEnterpriseContext(technicalFinding("secret-github-token"))
  ];

  const summary = summarizeGrcRisks(findings);

  assert.equal(summary.totalFindings, 2);
  assert.equal(summary.byCategory.some((entry) => entry.category === "AI application security"), true);
  assert.equal(summary.byFramework.some((entry) => entry.framework === "owasp-llm-2025"), true);
  assert.equal(summary.controlGaps.some((entry) => entry.controlGap === "least privilege"), true);
});
