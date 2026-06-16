# Enterprise Readiness Risk Mapping Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make VibeGuard enterprise-ready as a technical AI application security scanner with GRC risk mapping, while excluding CI/CD integration and operational documentation.

**Architecture:** Scanner rules remain developer/security-team evidence producers. A separate enterprise context layer enriches each technical finding with versioned rule metadata, framework mappings, risk classification, and control gaps for GRC reporting. Policy enforcement owns blocking and exception handling; output formatters render technical reports and risk summaries from the same normalized finding data.

**Tech Stack:** Node 20+, npm workspaces, TypeScript syntax executed by Node's type stripping, Node's built-in test runner, no required runtime service.

---

## Explicit Scope

Included:
- Versioned rule metadata and stable rule taxonomy.
- Framework crosswalks for OWASP LLM 2025, NIST AI RMF, MITRE ATLAS, and Google SAIF.
- GRC risk mapping derived from technical findings.
- Auditable suppression and exception metadata.
- Additional technical AI security scanners.
- JSON, Markdown, HTML, SARIF, and dedicated risk JSON output changes.
- Test coverage for rule metadata, crosswalks, policy behavior, output behavior, and scanner behavior.

Excluded by request:
- CI/CD integration.
- Operational documentation.

## File Structure

- Modify: `packages/core/src/types.ts` - add enterprise metadata, risk, framework, exception, scanner, and output types.
- Create: `packages/core/src/frameworks/types.ts` - framework and risk-mapping type helpers.
- Create: `packages/core/src/frameworks/catalog.ts` - framework catalog with version/source metadata.
- Create: `packages/core/src/frameworks/crosswalk.ts` - rule-to-framework and rule-to-risk mapping.
- Create: `packages/core/src/risk.ts` - GRC risk summary aggregation.
- Modify: `packages/core/src/engine.ts` - enrich findings before policy filtering.
- Modify: `packages/core/src/policy.ts` - parse and enforce enterprise suppression requirements.
- Modify: `packages/core/src/explain.ts` - include rule version and framework mappings in rule explanations.
- Inspect: `packages/scanners/src/utils.ts` - keep scanner findings evidence-only and avoid framework imports.
- Create: `packages/scanners/src/ai.ts` - high-confidence AI application technical scanner.
- Modify: `packages/scanners/src/index.ts` - register `ai`.
- Modify: `packages/output/src/formatters.ts` - render framework/risk context and `risk-json`.
- Modify: `packages/cli/src/cli.ts` - parse `--format risk-json` and suppression audit flags.
- Modify: `vibeguard.yml.example` - include enterprise policy defaults.
- Create: `tests/frameworks.test.ts` - framework catalog, crosswalk, and risk summary tests.
- Modify: `tests/policy-output.test.ts` - enterprise policy and formatter tests.
- Modify: `tests/scanners.test.ts` - AI scanner tests.
- Modify: `tests/cli.test.ts` - CLI format and suppression flag tests.

## Tasks

### Task 1: Enterprise Finding Types And Framework Crosswalk

**Files:**
- Modify: `packages/core/src/types.ts`
- Create: `packages/core/src/frameworks/types.ts`
- Create: `packages/core/src/frameworks/catalog.ts`
- Create: `packages/core/src/frameworks/crosswalk.ts`
- Create: `packages/core/src/risk.ts`
- Create: `tests/frameworks.test.ts`

- [ ] **Step 1: Write failing framework enrichment tests**

Create `tests/frameworks.test.ts`:

```ts
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
```

- [ ] **Step 2: Run tests to verify failure**

Run: `node --test tests/frameworks.test.ts`

Expected: FAIL with module-not-found errors for `frameworks/crosswalk.ts` and `risk.ts`.

- [ ] **Step 3: Add enterprise types**

Modify `packages/core/src/types.ts`:

```ts
export type FrameworkId = "owasp-llm-2025" | "nist-ai-rmf" | "mitre-atlas" | "google-saif";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type RuleStability = "stable" | "experimental" | "custom";

export type RuleMetadata = {
  id: string;
  name: string;
  version: string;
  stability: RuleStability;
  scanner?: ScannerName;
};

export type FrameworkMapping = {
  framework: FrameworkId;
  id: string;
  name: string;
  sourceVersion: string;
};

export type GrcRisk = {
  category: string;
  likelihood: RiskLevel;
  impact: RiskLevel;
  severity: RiskLevel;
  controlOwner: "engineering" | "security" | "grc" | "platform";
};
```

Extend `Finding`:

```ts
  rule?: RuleMetadata;
  frameworks?: FrameworkMapping[];
  risk?: GrcRisk;
  controlGaps?: string[];
```

Set defaults in `createFinding`:

```ts
    rule: input.rule,
    frameworks: input.frameworks ?? [],
    risk: input.risk,
    controlGaps: input.controlGaps ?? [],
```

- [ ] **Step 4: Create framework catalog**

Create `packages/core/src/frameworks/types.ts`:

```ts
import type { FrameworkId, FrameworkMapping, GrcRisk, RuleMetadata } from "../types.ts";

export type FrameworkCatalogEntry = {
  id: FrameworkId;
  name: string;
  sourceVersion: string;
  sourceUrl: string;
};

export type RuleEnterpriseContext = {
  rule: RuleMetadata;
  frameworks: FrameworkMapping[];
  risk: GrcRisk;
  controlGaps: string[];
};
```

Create `packages/core/src/frameworks/catalog.ts`:

```ts
import type { FrameworkCatalogEntry } from "./types.ts";

export const FRAMEWORK_CATALOG: FrameworkCatalogEntry[] = [
  {
    id: "owasp-llm-2025",
    name: "OWASP Top 10 for LLM Applications",
    sourceVersion: "2025",
    sourceUrl: "https://genai.owasp.org/llm-top-10/"
  },
  {
    id: "nist-ai-rmf",
    name: "NIST AI Risk Management Framework",
    sourceVersion: "AI RMF 1.0 + GenAI Profile",
    sourceUrl: "https://www.nist.gov/itl/ai-risk-management-framework"
  },
  {
    id: "mitre-atlas",
    name: "MITRE ATLAS",
    sourceVersion: "2026 public knowledge base",
    sourceUrl: "https://atlas.mitre.org/"
  },
  {
    id: "google-saif",
    name: "Google Secure AI Framework",
    sourceVersion: "SAIF 2.0",
    sourceUrl: "https://saif.google/"
  }
];
```

- [ ] **Step 5: Create crosswalk enrichment**

Create `packages/core/src/frameworks/crosswalk.ts`:

```ts
import type { Finding, RuleMetadata } from "../types.ts";
import type { RuleEnterpriseContext } from "./types.ts";

const RULE_VERSION = "2026.06.11";

const DEFAULT_CONTEXT = (ruleId: string): RuleEnterpriseContext => ({
  rule: {
    id: ruleId,
    name: ruleId,
    version: RULE_VERSION,
    stability: "custom"
  },
  frameworks: [],
  risk: {
    category: "Unmapped technical finding",
    likelihood: "medium",
    impact: "medium",
    severity: "medium",
    controlOwner: "security"
  },
  controlGaps: []
});

const CONTEXT_BY_RULE: Record<string, RuleEnterpriseContext> = {
  "js-eval": {
    rule: stableRule("js-eval", "JavaScript eval usage", "code"),
    frameworks: [
      { framework: "owasp-llm-2025", id: "LLM05:2025", name: "Improper Output Handling", sourceVersion: "2025" },
      { framework: "nist-ai-rmf", id: "MEASURE", name: "Analyze and assess AI risks", sourceVersion: "AI RMF 1.0 + GenAI Profile" },
      { framework: "mitre-atlas", id: "AML.T0051", name: "LLM Prompt Injection", sourceVersion: "2026 public knowledge base" },
      { framework: "google-saif", id: "input-output-controls", name: "Input and output controls", sourceVersion: "SAIF 2.0" }
    ],
    risk: {
      category: "AI application security",
      likelihood: "high",
      impact: "high",
      severity: "high",
      controlOwner: "engineering"
    },
    controlGaps: ["unsafe code execution", "output handling", "least privilege"]
  },
  "secret-github-token": {
    rule: stableRule("secret-github-token", "GitHub token in changed code", "secrets"),
    frameworks: [
      { framework: "owasp-llm-2025", id: "LLM02:2025", name: "Sensitive Information Disclosure", sourceVersion: "2025" },
      { framework: "nist-ai-rmf", id: "MANAGE", name: "Prioritize and respond to AI risks", sourceVersion: "AI RMF 1.0 + GenAI Profile" },
      { framework: "google-saif", id: "secure-secrets", name: "Secure secrets and credentials", sourceVersion: "SAIF 2.0" }
    ],
    risk: {
      category: "Credential exposure",
      likelihood: "high",
      impact: "high",
      severity: "high",
      controlOwner: "security"
    },
    controlGaps: ["secret management", "credential rotation", "source control hygiene"]
  }
};

export function enrichFindingWithEnterpriseContext(finding: Finding): Finding {
  const context = CONTEXT_BY_RULE[finding.ruleId] ?? DEFAULT_CONTEXT(finding.ruleId);
  return {
    ...finding,
    rule: finding.rule ?? context.rule,
    frameworks: finding.frameworks?.length ? finding.frameworks : context.frameworks,
    risk: finding.risk ?? context.risk,
    controlGaps: finding.controlGaps?.length ? finding.controlGaps : context.controlGaps
  };
}

function stableRule(id: string, name: string, scanner: RuleMetadata["scanner"]): RuleMetadata {
  return {
    id,
    name,
    version: RULE_VERSION,
    stability: "stable",
    scanner
  };
}
```

- [ ] **Step 6: Create GRC risk aggregation**

Create `packages/core/src/risk.ts`:

```ts
import type { Finding, FrameworkId, RiskLevel } from "./types.ts";

export type GrcRiskSummary = {
  totalFindings: number;
  byCategory: Array<{ category: string; count: number; highestSeverity: RiskLevel }>;
  byFramework: Array<{ framework: FrameworkId; count: number }>;
  controlGaps: Array<{ controlGap: string; count: number }>;
};

export function summarizeGrcRisks(findings: Finding[]): GrcRiskSummary {
  const byCategory = new Map<string, { count: number; highestSeverity: RiskLevel }>();
  const byFramework = new Map<FrameworkId, number>();
  const controlGaps = new Map<string, number>();

  for (const finding of findings) {
    if (finding.risk) {
      const current = byCategory.get(finding.risk.category) ?? { count: 0, highestSeverity: "low" };
      current.count += 1;
      current.highestSeverity = higherRisk(current.highestSeverity, finding.risk.severity);
      byCategory.set(finding.risk.category, current);
    }

    for (const mapping of finding.frameworks ?? []) {
      byFramework.set(mapping.framework, (byFramework.get(mapping.framework) ?? 0) + 1);
    }

    for (const gap of finding.controlGaps ?? []) {
      controlGaps.set(gap, (controlGaps.get(gap) ?? 0) + 1);
    }
  }

  return {
    totalFindings: findings.length,
    byCategory: [...byCategory.entries()].map(([category, value]) => ({ category, ...value })),
    byFramework: [...byFramework.entries()].map(([framework, count]) => ({ framework, count })),
    controlGaps: [...controlGaps.entries()].map(([controlGap, count]) => ({ controlGap, count }))
  };
}

function higherRisk(left: RiskLevel, right: RiskLevel): RiskLevel {
  const rank = { low: 1, medium: 2, high: 3, critical: 4 };
  return rank[right] > rank[left] ? right : left;
}
```

- [ ] **Step 7: Run framework tests**

Run: `node --test tests/frameworks.test.ts`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/frameworks/types.ts packages/core/src/frameworks/catalog.ts packages/core/src/frameworks/crosswalk.ts packages/core/src/risk.ts tests/frameworks.test.ts
git commit -m "feat: add enterprise finding context"
```

### Task 2: Enrich Findings In The Engine And Preserve Technical Output

**Files:**
- Modify: `packages/core/src/engine.ts`
- Inspect: `packages/scanners/src/utils.ts`
- Modify: `tests/policy-output.test.ts`

- [ ] **Step 1: Write failing engine enrichment test**

Add to `tests/policy-output.test.ts`:

```ts
import { runCheckFromDiff } from "../packages/core/src/engine.ts";

test("runCheck enriches findings with enterprise context before rendering", async () => {
  const diff = [
    "diff --git a/src/app.js b/src/app.js",
    "--- a/src/app.js",
    "+++ b/src/app.js",
    "@@ -1,0 +1 @@",
    "+eval(req.body.code);"
  ].join("\n");

  const report = await runCheckFromDiff(diff);

  assert.equal(report.findings[0].rule?.version, "2026.06.11");
  assert.equal(report.findings[0].frameworks?.some((entry) => entry.framework === "owasp-llm-2025"), true);
  assert.equal(report.findings[0].risk?.category, "AI application security");
  assert.equal(report.findings[0].snippet, "eval(req.body.code);");
});
```

- [ ] **Step 2: Run test to verify failure**

Run: `node --test tests/policy-output.test.ts`

Expected: FAIL because `runCheck` does not enrich findings with enterprise context.

- [ ] **Step 3: Enrich findings centrally**

Modify `packages/core/src/engine.ts`:

```ts
import { enrichFindingWithEnterpriseContext } from "./frameworks/crosswalk.ts";
```

Replace the `filtered` input with:

```ts
  const enrichedFindings = [...scannerFindings, ...vulnerabilityFindings]
    .map(enrichFindingWithEnterpriseContext);
  const filtered = filterFindings(
    applyPolicy(enrichedFindings, policy),
    options.minConfidence ?? policy.minConfidence,
    options.maxFindings,
    options.baselineFindingIds
  );
```

- [ ] **Step 4: Keep scanner helper evidence-only**

Confirm `packages/scanners/src/utils.ts` still only normalizes scanner findings and does not import framework files:

```ts
export function scannerFinding(input: {
  ruleId: string;
  title: string;
  severity: Severity;
  confidence: Confidence;
  riskScore: number;
  file: string;
  line: number;
  snippet: string;
  owasp?: OwaspLlmCategory;
  evidence?: string;
  attackPath?: string;
  impact?: string;
  why: string;
  suggestedFix: string;
  testSuggestion: string;
}): Finding {
  const snippet = input.snippet.trim();
  return createFinding({
    ...input,
    snippet,
    aiFixPrompt: generateAiFixPrompt({ ...input, snippet })
  });
}
```

- [ ] **Step 5: Run policy-output tests**

Run: `node --test tests/policy-output.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add packages/core/src/engine.ts tests/policy-output.test.ts
git commit -m "feat: enrich findings with enterprise context"
```

### Task 3: Risk JSON And GRC Report Sections

**Files:**
- Modify: `packages/core/src/types.ts`
- Modify: `packages/output/src/formatters.ts`
- Modify: `packages/cli/src/cli.ts`
- Modify: `tests/policy-output.test.ts`
- Modify: `tests/cli.test.ts`

- [ ] **Step 1: Write failing formatter tests**

Add to `tests/policy-output.test.ts`:

```ts
import { renderRiskJson } from "../packages/output/src/formatters.ts";

test("risk JSON summarizes GRC risk without hiding technical evidence links", () => {
  const findings = applyPolicy([finding({
    rule: { id: "js-eval", name: "JavaScript eval usage", version: "2026.06.11", stability: "stable", scanner: "code" },
    frameworks: [{ framework: "owasp-llm-2025", id: "LLM05:2025", name: "Improper Output Handling", sourceVersion: "2025" }],
    risk: { category: "AI application security", likelihood: "high", impact: "high", severity: "high", controlOwner: "engineering" },
    controlGaps: ["unsafe code execution"]
  })], defaultPolicy());

  const riskReport = JSON.parse(renderRiskJson(findings));

  assert.equal(riskReport.tool, "vibeguard");
  assert.equal(riskReport.reportType, "grc-risk");
  assert.equal(riskReport.riskSummary.totalFindings, 1);
  assert.equal(riskReport.risks[0].technicalEvidence[0].ruleId, "js-eval");
  assert.equal(riskReport.risks[0].technicalEvidence[0].file, "src/app.js");
  assert.equal(riskReport.risks[0].technicalEvidence[0].line, 3);
});
```

Add to `tests/cli.test.ts`:

```ts
test("parseArgs supports risk-json format", () => {
  const command = parseArgs(["check", "--staged", "--format", "risk-json"]);

  assert.equal(command.name, "check");
  assert.equal(command.format, "risk-json");
});
```

- [ ] **Step 2: Run tests to verify failure**

Run: `node --test tests/policy-output.test.ts tests/cli.test.ts`

Expected: FAIL because `risk-json` and `renderRiskJson` do not exist.

- [ ] **Step 3: Add output format type**

Modify `packages/core/src/types.ts`:

```ts
export type OutputFormat = "table" | "json" | "sarif" | "markdown" | "html" | "risk-json";
```

- [ ] **Step 4: Add risk JSON formatter**

Modify `packages/output/src/formatters.ts`:

```ts
import { summarizeGrcRisks } from "../../core/src/risk.ts";
```

Add:

```ts
export function renderRiskJson(reportLike: ReportLike): string {
  const report = normalizeReport(reportLike);
  const byRiskCategory = groupFindingsByRiskCategory(report.findings);

  return JSON.stringify(
    {
      tool: "vibeguard",
      version: "0.1.0",
      reportType: "grc-risk",
      summary: report.summary,
      riskSummary: summarizeGrcRisks(report.findings),
      risks: Object.entries(byRiskCategory).map(([category, findings]) => ({
        category,
        severity: highestRiskSeverity(findings),
        frameworks: uniqueFrameworks(findings),
        controlGaps: uniqueStrings(findings.flatMap((finding) => finding.controlGaps ?? [])),
        technicalEvidence: findings.map((finding) => ({
          id: finding.id,
          ruleId: finding.ruleId,
          ruleVersion: finding.rule?.version,
          severity: finding.severity,
          confidence: finding.confidence,
          file: finding.file,
          line: finding.line,
          scanner: finding.scanner,
          impact: finding.impact ?? finding.why,
          suggestedFix: finding.suggestedFix,
          blocking: finding.blocking
        }))
      }))
    },
    null,
    2
  );
}
```

Add helper functions:

```ts
function groupFindingsByRiskCategory(findings: Finding[]): Record<string, Finding[]> {
  return findings.reduce<Record<string, Finding[]>>((groups, finding) => {
    const category = finding.risk?.category ?? "Unmapped technical finding";
    groups[category] = groups[category] ?? [];
    groups[category].push(finding);
    return groups;
  }, {});
}

function highestRiskSeverity(findings: Finding[]): string {
  return [...findings]
    .sort((left, right) => severityRank(right.risk?.severity ?? right.severity) - severityRank(left.risk?.severity ?? left.severity))[0]
    ?.risk?.severity ?? "medium";
}

function uniqueFrameworks(findings: Finding[]) {
  const entries = new Map<string, NonNullable<Finding["frameworks"]>[number]>();
  for (const finding of findings) {
    for (const mapping of finding.frameworks ?? []) {
      entries.set(`${mapping.framework}:${mapping.id}`, mapping);
    }
  }
  return [...entries.values()];
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values)].sort();
}
```

Update `renderFindings`:

```ts
  if (format === "risk-json") return renderRiskJson(reportLike);
```

- [ ] **Step 5: Render GRC sections in Markdown and HTML**

Modify `renderMarkdown` to add this section after OWASP mapping:

```ts
  const grcSummary = summarizeGrcRisks(findings);
  lines.push("### GRC Risk Mapping", "");
  if (grcSummary.totalFindings === 0) {
    lines.push("- No mapped GRC risks.", "");
  } else {
    for (const entry of grcSummary.byCategory) {
      lines.push(`- ${entry.category}: ${entry.count} finding${entry.count === 1 ? "" : "s"} (highest severity: ${entry.highestSeverity})`);
    }
    lines.push("");
  }
```

Modify `renderHtml` to add a section after OWASP mapping:

```ts
    "<section class=\"actions\">",
    "<h2>GRC Risk Mapping</h2>",
    summarizeGrcRisks(report.findings).byCategory.length === 0
      ? "<p>No mapped GRC risks.</p>"
      : `<ul>${summarizeGrcRisks(report.findings).byCategory.map((entry) => `<li><strong>${escapeHtml(entry.category)}</strong>: ${entry.count} finding${entry.count === 1 ? "" : "s"} (highest severity: ${escapeHtml(entry.highestSeverity)})</li>`).join("")}</ul>`,
    "</section>",
```

- [ ] **Step 6: Add CLI format parsing**

Modify `packages/cli/src/cli.ts`:

```ts
function isOutputFormat(value: string | undefined): value is OutputFormat {
  return value === "table" || value === "json" || value === "sarif" || value === "markdown" || value === "html" || value === "risk-json";
}
```

Change the invalid format error:

```ts
if (!isOutputFormat(value)) throw new Error("Format must be table, json, sarif, markdown, html, or risk-json");
```

Update help text:

```ts
"  vibeguard check [path] [--format table|json|sarif|markdown|html|risk-json]",
```

- [ ] **Step 7: Run formatter and CLI tests**

Run: `node --test tests/policy-output.test.ts tests/cli.test.ts`

Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add packages/core/src/types.ts packages/output/src/formatters.ts packages/cli/src/cli.ts tests/policy-output.test.ts tests/cli.test.ts
git commit -m "feat: add grc risk reporting"
```

### Task 4: Enterprise Suppression And Exception Controls

**Files:**
- Modify: `packages/core/src/types.ts`
- Modify: `packages/core/src/policy.ts`
- Modify: `packages/cli/src/cli.ts`
- Modify: `vibeguard.yml.example`
- Modify: `tests/policy-output.test.ts`
- Modify: `tests/cli.test.ts`

- [ ] **Step 1: Write failing suppression policy tests**

Add to `tests/policy-output.test.ts`:

```ts
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
    "    reason: accepted for migration window",
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
    "    reason: old acceptance",
    "    reviewer: security@example.com",
    "    expires: 2020-01-01"
  ].join("\n"));

  const results = applyPolicy([finding()], policy);

  assert.equal(results.length, 1);
  assert.equal(results[0].blocking, true);
});
```

Add to `tests/cli.test.ts`:

```ts
test("parseArgs supports enterprise suppression audit fields", () => {
  const command = parseArgs([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-01-01"
  ]);

  assert.equal(command.name, "suppress");
  assert.equal(command.reviewer, "security@example.com");
  assert.equal(command.expires, "2099-01-01");
});
```

- [ ] **Step 2: Run tests to verify failure**

Run: `node --test tests/policy-output.test.ts tests/cli.test.ts`

Expected: FAIL because suppression policy fields are not typed, parsed, or enforced.

- [ ] **Step 3: Extend suppression types**

Modify `packages/core/src/types.ts`:

```ts
export type Suppression = {
  rule?: string;
  file?: string;
  line?: number;
  reason?: string;
  reviewer?: string;
  expires?: string;
};

export type SuppressionPolicy = {
  requireReason: boolean;
  requireReviewer: boolean;
  requireExpiration: boolean;
};
```

Extend `Policy`:

```ts
  suppressionPolicy: SuppressionPolicy;
```

- [ ] **Step 4: Add default enterprise suppression policy**

Modify `defaultPolicy()` in `packages/core/src/policy.ts`:

```ts
    suppressionPolicy: {
      requireReason: true,
      requireReviewer: true,
      requireExpiration: true
    },
```

Modify `DEFAULT_POLICY_TEXT`:

```yaml
suppressionPolicy:
  requireReason: true
  requireReviewer: true
  requireExpiration: true
```

- [ ] **Step 5: Parse suppression policy and fields**

Modify `loadPolicyFromText` to parse booleans under `suppressionPolicy`:

```ts
    if (section === "suppressionPolicy" && trimmed.includes(":")) {
      const [key, ...rest] = trimmed.split(":");
      const value = rest.join(":").trim();
      if (key.trim() === "requireReason") policy.suppressionPolicy.requireReason = parseBoolean(value);
      if (key.trim() === "requireReviewer") policy.suppressionPolicy.requireReviewer = parseBoolean(value);
      if (key.trim() === "requireExpiration") policy.suppressionPolicy.requireExpiration = parseBoolean(value);
      continue;
    }
```

Add:

```ts
function parseBoolean(value: string): boolean {
  return value === "true";
}
```

Modify `assignSuppressionValue`:

```ts
  if (key === "reviewer") suppression.reviewer = value;
  if (key === "expires") suppression.expires = value;
```

- [ ] **Step 6: Enforce enterprise suppression validity**

Modify `isSuppressed`:

```ts
export function isSuppressed(finding: Finding, suppressions: Suppression[], suppressionPolicy = defaultPolicy().suppressionPolicy): boolean {
  return suppressions.some((suppression) => {
    if (!isValidSuppression(suppression, suppressionPolicy)) return false;
    if (suppression.rule && suppression.rule !== finding.ruleId && suppression.rule !== finding.id) return false;
    if (suppression.file && !globMatches(suppression.file, finding.file)) return false;
    if (suppression.line && suppression.line !== finding.line) return false;
    return true;
  });
}
```

Modify `applyPolicy`:

```ts
    .filter((finding) => !isSuppressed(finding, policy.suppressions, policy.suppressionPolicy))
```

Add:

```ts
function isValidSuppression(suppression: Suppression, policy: Policy["suppressionPolicy"]): boolean {
  if (policy.requireReason && !suppression.reason) return false;
  if (policy.requireReviewer && !suppression.reviewer) return false;
  if (policy.requireExpiration && !suppression.expires) return false;
  if (suppression.expires && Date.parse(`${suppression.expires}T00:00:00Z`) < Date.now()) return false;
  return true;
}
```

- [ ] **Step 7: Add CLI suppression audit flags**

Modify `ParsedCommand` in `packages/cli/src/cli.ts`:

```ts
  | { name: "suppress"; id: string; file?: string; line?: number; reason?: string; reviewer?: string; expires?: string; config?: string }
```

Add parsing branches:

```ts
      } else if (arg === "--reviewer") {
        reviewer = requiredValue(rest[index + 1], "--reviewer");
        index += 1;
      } else if (arg === "--expires") {
        expires = requiredValue(rest[index + 1], "--expires");
        index += 1;
```

Return:

```ts
    return { name: "suppress", id, file, line, reason, reviewer, expires, config };
```

Modify `addSuppression` block:

```ts
    command.reviewer ? `    reviewer: ${yamlScalar(command.reviewer)}` : undefined,
    command.expires ? `    expires: ${yamlScalar(command.expires)}` : undefined
```

- [ ] **Step 8: Update example policy**

Modify `vibeguard.yml.example`:

```yaml
suppressionPolicy:
  requireReason: true
  requireReviewer: true
  requireExpiration: true
```

- [ ] **Step 9: Run policy and CLI tests**

Run: `node --test tests/policy-output.test.ts tests/cli.test.ts`

Expected: PASS.

- [ ] **Step 10: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/policy.ts packages/cli/src/cli.ts vibeguard.yml.example tests/policy-output.test.ts tests/cli.test.ts
git commit -m "feat: add enterprise suppression controls"
```

### Task 5: Technical AI Application Scanner

**Files:**
- Modify: `packages/core/src/types.ts`
- Modify: `packages/core/src/policy.ts`
- Create: `packages/scanners/src/ai.ts`
- Modify: `packages/scanners/src/index.ts`
- Modify: `vibeguard.yml.example`
- Modify: `tests/scanners.test.ts`

- [ ] **Step 1: Write failing AI scanner tests**

Add to `tests/scanners.test.ts`:

```ts
import { runAiScanner } from "../packages/scanners/src/ai.ts";

test("AI scanner detects unsafe agent tool and RAG patterns", () => {
  const findings = runAiScanner([
    file("src/agent.ts", [
      'tools: [{ name: "run_shell", execute: ({ command }) => exec(command) }]',
      "await vectorStore.similaritySearch(query, 50);",
      "const result = await openai.chat.completions.create({ messages, max_tokens: 100000 });"
    ])
  ]);

  assert.equal(findings.some((finding) => finding.ruleId === "ai-agent-shell-tool-no-approval"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "ai-rag-query-without-filter"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "ai-unbounded-token-request"), true);
});

test("AI scanner detects unsafe model supply chain flags", () => {
  const findings = runAiScanner([
    file("model.py", [
      "model = AutoModel.from_pretrained(model_id, trust_remote_code=True)"
    ])
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "ai-model-trust-remote-code");
  assert.equal(findings[0].severity, "critical");
});
```

- [ ] **Step 2: Run tests to verify failure**

Run: `node --test tests/scanners.test.ts`

Expected: FAIL because `packages/scanners/src/ai.ts` does not exist.

- [ ] **Step 3: Add scanner name**

Modify `packages/core/src/types.ts`:

```ts
export type ScannerName = "code" | "secrets" | "dependencies" | "docker" | "actions" | "sensitive-files" | "ai";
```

Modify `DEFAULT_SCANNERS` in `packages/core/src/policy.ts`:

```ts
  "ai"
```

- [ ] **Step 4: Create AI scanner**

Create `packages/scanners/src/ai.ts`:

```ts
import type { DiffFile, Finding } from "../../core/src/types.ts";
import { owaspCategory } from "../../core/src/owasp.ts";
import { scannerFinding } from "./utils.ts";

type AiRule = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  riskScore: number;
  pattern: RegExp;
  evidence: string;
  attackPath: string;
  impact: string;
  why: string;
  fix: string;
  test: string;
  owasp?: ReturnType<typeof owaspCategory>;
};

const AI_RULES: AiRule[] = [
  {
    id: "ai-agent-shell-tool-no-approval",
    title: "Agent shell tool lacks visible approval boundary",
    severity: "critical",
    confidence: "high",
    riskScore: 96,
    pattern: /(tools\s*:\s*\[|tool\s*\()[^\n]*(run_shell|shell|exec|spawn|terminal|command)/i,
    owasp: owaspCategory("LLM06:2025"),
    evidence: "An agent tool exposes shell or command execution in the tool registration path.",
    attackPath: "Prompt or retrieved content influences agent action -> agent selects shell tool -> command executes without a visible approval gate.",
    impact: "This can become arbitrary command execution through agent tool use.",
    why: "Agent tools with shell capability need explicit approval gates, allowlists, and audit logging.",
    fix: "Require human approval for shell tools, restrict commands to an allowlist, and pass arguments as structured data.",
    test: "Add a test where a prompt asks the agent to run an unexpected command and prove the tool call is rejected."
  },
  {
    id: "ai-rag-query-without-filter",
    title: "Vector retrieval lacks tenant or authorization filter",
    severity: "high",
    confidence: "medium",
    riskScore: 78,
    pattern: /\.(similaritySearch|query|retrieve)\s*\([^)]*(query|input)[^)]*\)/i,
    owasp: owaspCategory("LLM08:2025"),
    evidence: "A vector retrieval call uses query input without a visible metadata filter.",
    attackPath: "User controls retrieval query -> vector store searches all indexed content -> cross-tenant or sensitive context can enter the model.",
    impact: "RAG retrieval can disclose documents outside the caller's authorization boundary.",
    why: "RAG systems need metadata filters that enforce tenant and document-level authorization.",
    fix: "Add tenant, user, and document authorization filters to the retrieval call.",
    test: "Add a test proving a user cannot retrieve another tenant's document through semantic search."
  },
  {
    id: "ai-unbounded-token-request",
    title: "LLM request uses excessive token budget",
    severity: "medium",
    confidence: "high",
    riskScore: 68,
    pattern: /max[_-]?tokens\s*:\s*(?:[1-9]\d{4,}|Infinity)/i,
    owasp: owaspCategory("LLM10:2025"),
    evidence: "An LLM call sets an excessive or unbounded token budget.",
    attackPath: "Attacker triggers long request or response -> model consumes excessive tokens -> service cost or availability is impacted.",
    impact: "Unbounded token use can create denial-of-wallet or degraded availability.",
    why: "Enterprise deployments need bounded token budgets per request and per user.",
    fix: "Set model-specific maximum token budgets and enforce per-user rate limits.",
    test: "Add a test proving requests above the configured token budget are rejected."
  },
  {
    id: "ai-model-trust-remote-code",
    title: "Model loading trusts remote code",
    severity: "critical",
    confidence: "high",
    riskScore: 98,
    pattern: /trust_remote_code\s*=\s*True/i,
    owasp: owaspCategory("LLM03:2025"),
    evidence: "Model loading enables trust_remote_code=True.",
    attackPath: "Application downloads model artifact -> remote model repository supplies code -> runtime executes repository code.",
    impact: "A compromised model repository can execute arbitrary code during model loading.",
    why: "Remote model code is supply-chain executable code and should not run without review.",
    fix: "Disable trust_remote_code, pin model revisions, and review model code before allowing execution.",
    test: "Add a test or policy check that model loading rejects trust_remote_code=True."
  }
];

export function runAiScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];
  for (const file of files) {
    if (!isAiRelevantFile(file.path)) continue;
    for (const line of file.addedLines) {
      for (const rule of AI_RULES) {
        if (!rule.pattern.test(line.content)) continue;
        findings.push(scannerFinding({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          confidence: rule.confidence,
          riskScore: rule.riskScore,
          file: file.path,
          line: line.line,
          snippet: line.content,
          owasp: rule.owasp,
          evidence: rule.evidence,
          attackPath: rule.attackPath,
          impact: rule.impact,
          why: rule.why,
          suggestedFix: rule.fix,
          testSuggestion: rule.test
        }));
      }
    }
  }
  return findings;
}

function isAiRelevantFile(path: string): boolean {
  return /\.(cjs|mjs|js|jsx|ts|tsx|py)$/.test(path);
}
```

- [ ] **Step 5: Register AI scanner**

Modify `packages/scanners/src/index.ts`:

```ts
import { runAiScanner } from "./ai.ts";
```

Add to `SCANNERS`:

```ts
  ai: runAiScanner
```

Add to exports:

```ts
  runAiScanner,
```

- [ ] **Step 6: Update default config**

Modify `vibeguard.yml.example` and `DEFAULT_POLICY_TEXT` to include:

```yaml
  - ai
```

- [ ] **Step 7: Add crosswalk entries for AI scanner rules**

Modify `packages/core/src/frameworks/crosswalk.ts` by adding entries for:

```ts
"ai-agent-shell-tool-no-approval"
"ai-rag-query-without-filter"
"ai-unbounded-token-request"
"ai-model-trust-remote-code"
```

Use these risk categories:

```ts
"Agentic AI excessive agency"
"RAG data exposure"
"AI resource consumption"
"AI supply chain"
```

- [ ] **Step 8: Run scanner and framework tests**

Run: `node --test tests/scanners.test.ts tests/frameworks.test.ts`

Expected: PASS.

- [ ] **Step 9: Commit**

```bash
git add packages/core/src/types.ts packages/core/src/policy.ts packages/core/src/frameworks/crosswalk.ts packages/scanners/src/ai.ts packages/scanners/src/index.ts vibeguard.yml.example tests/scanners.test.ts
git commit -m "feat: add ai application scanner"
```

### Task 6: Rule Explanation And Stability Metadata

**Files:**
- Modify: `packages/core/src/explain.ts`
- Modify: `tests/cli.test.ts`
- Modify: `tests/frameworks.test.ts`

- [ ] **Step 1: Write failing explanation tests**

Add to `tests/cli.test.ts`:

```ts
test("runCli explain includes enterprise rule metadata", async () => {
  const writes: string[] = [];
  const result = await runCli(["explain", "js-eval"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  const output = writes.join("");

  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("Rule version: 2026.06.11"), true);
  assert.equal(output.includes("Framework mappings:"), true);
  assert.equal(output.includes("OWASP Top 10 for LLM Applications"), true);
});
```

Add to `tests/frameworks.test.ts`:

```ts
test("stable built-in rules expose version metadata", () => {
  const enriched = enrichFindingWithEnterpriseContext(technicalFinding("ai-model-trust-remote-code"));

  assert.equal(enriched.rule?.version, "2026.06.11");
  assert.equal(enriched.rule?.stability, "stable");
});
```

- [ ] **Step 2: Run tests to verify failure**

Run: `node --test tests/cli.test.ts tests/frameworks.test.ts`

Expected: FAIL because `explainRule` does not include enterprise metadata.

- [ ] **Step 3: Enhance rule explanations**

Modify `packages/core/src/explain.ts`:

```ts
import { FRAMEWORK_CATALOG } from "./frameworks/catalog.ts";
import { enrichFindingWithEnterpriseContext } from "./frameworks/crosswalk.ts";
import { createFinding } from "./types.ts";
```

Add a helper:

```ts
function enterpriseContextForRule(ruleId: string) {
  return enrichFindingWithEnterpriseContext(createFinding({
    ruleId,
    title: ruleId,
    severity: "medium",
    confidence: "medium",
    riskScore: 50,
    file: "<rule>",
    line: 1,
    snippet: ruleId,
    why: "Rule explanation context.",
    suggestedFix: "Review the rule-specific suggested fix.",
    aiFixPrompt: "Review and fix the finding.",
    testSuggestion: "Add a regression test for this rule."
  }));
}
```

Append this block in `explainRule` before `join("\n")`:

```ts
  const context = enterpriseContextForRule(rule.ruleId);
  const frameworkNames = (context.frameworks ?? []).map((mapping) => {
    const framework = FRAMEWORK_CATALOG.find((entry) => entry.id === mapping.framework);
    return `${framework?.name ?? mapping.framework}: ${mapping.id} ${mapping.name}`;
  });
```

Return:

```ts
  return [
    `${rule.ruleId}: ${rule.title}`,
    "",
    `Rule version: ${context.rule?.version ?? "unversioned"}`,
    `Rule stability: ${context.rule?.stability ?? "custom"}`,
    `Risk category: ${context.risk?.category ?? "Unmapped technical finding"}`,
    "",
    `Why it matters: ${rule.why}`,
    `Suggested fix: ${rule.fix}`,
    "",
    "Framework mappings:",
    ...(frameworkNames.length ? frameworkNames.map((name) => `- ${name}`) : ["- No framework mapping"])
  ].join("\n");
```

- [ ] **Step 4: Run CLI and framework tests**

Run: `node --test tests/cli.test.ts tests/frameworks.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/core/src/explain.ts tests/cli.test.ts tests/frameworks.test.ts
git commit -m "feat: expose enterprise rule explanations"
```

### Task 7: Final Verification And Enterprise Readiness Gate

**Files:**
- No new files.
- Validate all changed source and test files from Tasks 1-6.

- [ ] **Step 1: Run full test suite**

Run: `npm test`

Expected: PASS.

- [ ] **Step 2: Run technical JSON report smoke test**

Run: `npm run vibeguard -- check --format json --max-findings 5`

Expected: exit `0` or `1`; output is valid JSON with:

```json
{
  "tool": "vibeguard",
  "owaspSummary": [],
  "findings": []
}
```

The arrays can contain findings when the repository currently has security findings.

- [ ] **Step 3: Run GRC risk JSON smoke test**

Run: `npm run vibeguard -- check --format risk-json --max-findings 5`

Expected: exit `0` or `1`; output is valid JSON with:

```json
{
  "tool": "vibeguard",
  "reportType": "grc-risk",
  "riskSummary": {
    "totalFindings": 0
  },
  "risks": []
}
```

The `totalFindings` and `risks` values can be non-zero when the repository currently has security findings.

- [ ] **Step 4: Run AI scanner fixture check through tests**

Run: `node --test tests/scanners.test.ts`

Expected: PASS with rules:

```text
ai-agent-shell-tool-no-approval
ai-rag-query-without-filter
ai-unbounded-token-request
ai-model-trust-remote-code
```

- [ ] **Step 5: Inspect git diff**

Run: `git diff --stat`

Expected: changed files are limited to:

```text
packages/core/src/types.ts
packages/core/src/frameworks/types.ts
packages/core/src/frameworks/catalog.ts
packages/core/src/frameworks/crosswalk.ts
packages/core/src/risk.ts
packages/core/src/engine.ts
packages/core/src/policy.ts
packages/core/src/explain.ts
packages/scanners/src/ai.ts
packages/scanners/src/index.ts
packages/output/src/formatters.ts
packages/cli/src/cli.ts
vibeguard.yml.example
tests/frameworks.test.ts
tests/policy-output.test.ts
tests/scanners.test.ts
tests/cli.test.ts
```

- [ ] **Step 6: Commit final verification adjustments**

If Task 7 required a source or test correction, commit it:

```bash
git add packages tests vibeguard.yml.example
git commit -m "test: verify enterprise readiness risk mapping"
```

If Task 7 required no corrections, do not create an empty commit.

## Enterprise Readiness Acceptance Criteria

- Technical findings remain file/line/rule/evidence based.
- Framework mappings are derived from technical rule IDs and do not replace scanner logic.
- Every built-in mapped rule has a rule version.
- Risk output links back to exact technical evidence.
- Suppressions require reason, reviewer, and expiration by default.
- Expired suppressions do not hide findings.
- AI scanner covers agent shell tools, RAG retrieval filters, excessive token budgets, and remote model code trust.
- `risk-json` is available without requiring source upload.
- Full test suite passes.
- No CI/CD integration task is included.
- No operational documentation task is included.
