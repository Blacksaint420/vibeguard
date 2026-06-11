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
