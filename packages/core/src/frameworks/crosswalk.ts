import type { Finding, FrameworkId, FrameworkMapping, RuleMetadata } from "../types.ts";
import { FRAMEWORK_CATALOG } from "./catalog.ts";
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
      frameworkMapping("owasp-llm-2025", "LLM05:2025", "Improper Output Handling"),
      frameworkMapping("nist-ai-rmf", "MEASURE", "Analyze and assess AI risks"),
      frameworkMapping("mitre-atlas", "AML.T0051", "LLM Prompt Injection"),
      frameworkMapping("google-saif", "input-output-controls", "Input and output controls")
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
      frameworkMapping("owasp-llm-2025", "LLM02:2025", "Sensitive Information Disclosure"),
      frameworkMapping("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMapping("google-saif", "secure-secrets", "Secure secrets and credentials")
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
  const rule = finding.rule ?? context.rule;
  const frameworks = finding.frameworks?.length ? finding.frameworks : context.frameworks;
  const risk = finding.risk ?? context.risk;
  const controlGaps = finding.controlGaps?.length ? finding.controlGaps : context.controlGaps;

  return {
    ...finding,
    rule: { ...rule },
    frameworks: frameworks.map((mapping) => ({ ...mapping })),
    risk: { ...risk },
    controlGaps: [...controlGaps]
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

function frameworkMapping(framework: FrameworkId, id: string, name: string): FrameworkMapping {
  const catalogEntry = FRAMEWORK_CATALOG.find((entry) => entry.id === framework);
  if (!catalogEntry) {
    throw new Error(`Unknown framework mapping: ${framework}`);
  }

  return {
    framework,
    id,
    name,
    sourceVersion: catalogEntry.sourceVersion
  };
}
