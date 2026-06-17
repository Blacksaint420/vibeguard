import test from "node:test";
import assert from "node:assert/strict";

import { createFinding } from "../packages/core/src/types.ts";
import { FRAMEWORK_CATALOG } from "../packages/core/src/frameworks/catalog.ts";
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

test("known unmapped built-in rules stay stable while unknown rules remain custom", () => {
  const builtIn = enrichFindingWithEnterpriseContext(technicalFinding("py-yaml-unsafe-load"));
  const custom = enrichFindingWithEnterpriseContext(technicalFinding("custom-rule"));

  assert.equal(builtIn.rule?.id, "py-yaml-unsafe-load");
  assert.equal(builtIn.rule?.version, "2026.06.11");
  assert.equal(builtIn.rule?.stability, "stable");
  assert.equal(builtIn.rule?.scanner, "code");
  assert.equal(builtIn.frameworks.length, 0);
  assert.equal(builtIn.risk?.category, "Unmapped technical finding");
  assert.equal(custom.rule?.stability, "custom");
});

test("stable built-in rules expose version metadata", () => {
  const enriched = enrichFindingWithEnterpriseContext(technicalFinding("ai-model-trust-remote-code"));

  assert.equal(enriched.rule?.version, "2026.06.11");
  assert.equal(enriched.rule?.stability, "stable");
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

test("framework catalog exposes expected IDs, source versions, and source URLs", () => {
  assert.deepEqual(
    FRAMEWORK_CATALOG.map((entry) => entry.id),
    ["owasp-llm-2025", "nist-ai-rmf", "mitre-atlas", "google-saif"]
  );
  assert.equal(Object.isFrozen(FRAMEWORK_CATALOG), true);
  assert.equal(FRAMEWORK_CATALOG.every((entry) => Object.isFrozen(entry)), true);
  assert.equal(FRAMEWORK_CATALOG.find((entry) => entry.id === "owasp-llm-2025")?.sourceVersion, "2025");
  assert.equal(FRAMEWORK_CATALOG.find((entry) => entry.id === "owasp-llm-2025")?.sourceUrl, "https://genai.owasp.org/llm-top-10/");
  assert.equal(FRAMEWORK_CATALOG.find((entry) => entry.id === "nist-ai-rmf")?.sourceVersion, "AI RMF 1.0 + GenAI Profile");
  assert.equal(
    FRAMEWORK_CATALOG.find((entry) => entry.id === "nist-ai-rmf")?.sourceUrl,
    "https://www.nist.gov/itl/ai-risk-management-framework"
  );
  assert.equal(FRAMEWORK_CATALOG.find((entry) => entry.id === "mitre-atlas")?.sourceVersion, "2026 public knowledge base");
  assert.equal(FRAMEWORK_CATALOG.find((entry) => entry.id === "mitre-atlas")?.sourceUrl, "https://atlas.mitre.org/");
  assert.equal(FRAMEWORK_CATALOG.find((entry) => entry.id === "google-saif")?.sourceVersion, "SAIF 2.0");
  assert.equal(FRAMEWORK_CATALOG.find((entry) => entry.id === "google-saif")?.sourceUrl, "https://saif.google/");
});

test("enriched framework mappings and control gaps are isolated between findings", () => {
  const first = enrichFindingWithEnterpriseContext(technicalFinding("js-eval"));

  first.controlGaps.push("mutated gap");
  first.frameworks[0].sourceVersion = "mutated";
  first.risk!.category = "Mutated risk category";
  first.frameworks.push({
    framework: "owasp-llm-2025",
    id: "MUTATED",
    name: "Mutated mapping",
    sourceVersion: "mutated"
  });

  const second = enrichFindingWithEnterpriseContext(technicalFinding("js-eval"));

  assert.deepEqual(second.controlGaps, ["unsafe code execution", "output handling", "least privilege"]);
  assert.equal(second.frameworks.some((entry) => entry.id === "MUTATED"), false);
  assert.equal(second.frameworks.find((entry) => entry.framework === "owasp-llm-2025")?.sourceVersion, "2025");
  assert.equal(second.risk?.category, "AI application security");
});

test("enriched crosswalk mapping source versions match the current framework catalog", () => {
  const catalogVersionById = new Map(FRAMEWORK_CATALOG.map((entry) => [entry.id, entry.sourceVersion]));
  const findings = [
    enrichFindingWithEnterpriseContext(technicalFinding("js-eval")),
    enrichFindingWithEnterpriseContext(technicalFinding("secret-github-token")),
    enrichFindingWithEnterpriseContext(technicalFinding("ai-agent-shell-tool-no-approval")),
    enrichFindingWithEnterpriseContext(technicalFinding("ai-rag-query-without-filter")),
    enrichFindingWithEnterpriseContext(technicalFinding("ai-unbounded-token-request")),
    enrichFindingWithEnterpriseContext(technicalFinding("ai-model-trust-remote-code"))
  ];

  for (const finding of findings) {
    for (const mapping of finding.frameworks) {
      assert.equal(mapping.sourceVersion, catalogVersionById.get(mapping.framework));
    }
  }
});

test("AI scanner rules map to enterprise AI risk categories", () => {
  assert.equal(enrichFindingWithEnterpriseContext(technicalFinding("ai-agent-shell-tool-no-approval")).risk?.category, "Agentic AI excessive agency");
  assert.equal(enrichFindingWithEnterpriseContext(technicalFinding("ai-rag-query-without-filter")).risk?.category, "RAG data exposure");
  assert.equal(enrichFindingWithEnterpriseContext(technicalFinding("ai-unbounded-token-request")).risk?.category, "AI resource consumption");
  assert.equal(enrichFindingWithEnterpriseContext(technicalFinding("ai-model-trust-remote-code")).risk?.category, "AI supply chain");
});

test("agent capability graph rules have enterprise mappings", () => {
  const enriched = enrichFindingWithEnterpriseContext(createFinding({
    ruleId: "agent-capability-shell-without-approval",
    title: "Agent can reach shell execution",
    severity: "critical",
    confidence: "high",
    riskScore: 97,
    file: "src/agent.ts",
    line: 2,
    snippet: "run_shell",
    evidence: "support-agent can reach run_shell.",
    attackPath: "Prompt injection reaches agent tool selection and shell execution.",
    impact: "Autonomous command execution in the application runtime.",
    why: "Shell access is a high-risk agent capability.",
    suggestedFix: "Require approval and command allowlists.",
    testSuggestion: "Add a test proving shell commands require approval.",
    aiFixPrompt: "Require approval."
  }));

  assert.equal(enriched.rule?.id, "agent-capability-shell-without-approval");
  assert.equal(enriched.rule?.scanner, "ai");
  assert.equal(enriched.risk?.category, "Agentic AI excessive agency");
  assert.equal(enriched.frameworks?.some((mapping) => mapping.framework === "owasp-llm-2025"), true);
});
