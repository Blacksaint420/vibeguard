import type { Finding, FrameworkId, FrameworkMapping, RuleMetadata } from "../types.ts";
import { FRAMEWORK_CATALOG } from "./catalog.ts";
import type { RuleEnterpriseContext } from "./types.ts";
import { BUILT_IN_RULE_VERSION, builtInRuleMetadata } from "../rules.ts";

type FrameworkMappingDefinition = Omit<FrameworkMapping, "sourceVersion">;
type RuleEnterpriseContextDefinition = Omit<RuleEnterpriseContext, "frameworks"> & {
  frameworks: FrameworkMappingDefinition[];
};

const DEFAULT_CONTEXT = (ruleId: string): RuleEnterpriseContextDefinition => ({
  rule: builtInRuleMetadata(ruleId) ?? {
    id: ruleId,
    name: ruleId,
    version: BUILT_IN_RULE_VERSION,
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

const CONTEXT_BY_RULE: Record<string, RuleEnterpriseContextDefinition> = {
  "js-eval": {
    rule: stableRule("js-eval", "JavaScript eval usage", "code"),
    frameworks: [
      frameworkMappingDefinition("owasp-llm-2025", "LLM05:2025", "Improper Output Handling"),
      frameworkMappingDefinition("nist-ai-rmf", "MEASURE", "Analyze and assess AI risks"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0051", "LLM Prompt Injection"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
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
      frameworkMappingDefinition("owasp-llm-2025", "LLM02:2025", "Sensitive Information Disclosure"),
      frameworkMappingDefinition("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMappingDefinition("google-saif", "secure-secrets", "Secure secrets and credentials")
    ],
    risk: {
      category: "Credential exposure",
      likelihood: "high",
      impact: "high",
      severity: "high",
      controlOwner: "security"
    },
    controlGaps: ["secret management", "credential rotation", "source control hygiene"]
  },
  "ai-agent-shell-tool-no-approval": {
    rule: stableRule("ai-agent-shell-tool-no-approval", "Agent tool exposes shell execution without approval", "ai"),
    frameworks: [
      frameworkMappingDefinition("owasp-llm-2025", "LLM06:2025", "Excessive Agency"),
      frameworkMappingDefinition("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0051", "LLM Prompt Injection"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
    ],
    risk: {
      category: "Agentic AI excessive agency",
      likelihood: "high",
      impact: "critical",
      severity: "critical",
      controlOwner: "engineering"
    },
    controlGaps: ["tool approval", "least privilege", "command allowlisting"]
  },
  "ai-rag-query-without-filter": {
    rule: stableRule("ai-rag-query-without-filter", "RAG retrieval query has no visible authorization filter", "ai"),
    frameworks: [
      frameworkMappingDefinition("owasp-llm-2025", "LLM08:2025", "Vector and Embedding Weaknesses"),
      frameworkMappingDefinition("nist-ai-rmf", "MAP", "Map AI context and risks"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0054", "LLM Data Leakage"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
    ],
    risk: {
      category: "RAG data exposure",
      likelihood: "medium",
      impact: "high",
      severity: "high",
      controlOwner: "engineering"
    },
    controlGaps: ["retrieval authorization", "tenant isolation", "data minimization"]
  },
  "ai-unbounded-token-request": {
    rule: stableRule("ai-unbounded-token-request", "LLM request uses excessive token budget", "ai"),
    frameworks: [
      frameworkMappingDefinition("owasp-llm-2025", "LLM10:2025", "Unbounded Consumption"),
      frameworkMappingDefinition("nist-ai-rmf", "MEASURE", "Analyze and assess AI risks"),
      frameworkMappingDefinition("google-saif", "secure-by-default", "Secure-by-default deployment")
    ],
    risk: {
      category: "AI resource consumption",
      likelihood: "medium",
      impact: "medium",
      severity: "medium",
      controlOwner: "platform"
    },
    controlGaps: ["rate limiting", "cost controls", "resource quotas"]
  },
  "ai-model-trust-remote-code": {
    rule: stableRule("ai-model-trust-remote-code", "Model loading trusts remote code", "ai"),
    frameworks: [
      frameworkMappingDefinition("owasp-llm-2025", "LLM03:2025", "Supply Chain"),
      frameworkMappingDefinition("nist-ai-rmf", "GOVERN", "Govern AI risk management"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0010", "Acquire ML Artifacts"),
      frameworkMappingDefinition("google-saif", "secure-supply-chain", "Secure supply chain")
    ],
    risk: {
      category: "AI supply chain",
      likelihood: "high",
      impact: "critical",
      severity: "critical",
      controlOwner: "security"
    },
    controlGaps: ["model provenance", "artifact pinning", "supply chain review"]
  }
};

export function enrichFindingWithEnterpriseContext(finding: Finding): Finding {
  const context = CONTEXT_BY_RULE[finding.ruleId] ?? DEFAULT_CONTEXT(finding.ruleId);
  const knownBuiltInRule = builtInRuleMetadata(finding.ruleId);
  const rule = knownBuiltInRule
    ? {
        ...knownBuiltInRule,
        ...(finding.rule ?? {}),
        id: knownBuiltInRule.id,
        version: knownBuiltInRule.version,
        stability: knownBuiltInRule.stability,
        scanner: finding.rule?.scanner ?? knownBuiltInRule.scanner
      }
    : finding.rule ?? context.rule;
  const frameworks = finding.frameworks?.length ? finding.frameworks : context.frameworks;
  const risk = finding.risk ?? context.risk;
  const controlGaps = finding.controlGaps?.length ? finding.controlGaps : context.controlGaps;

  return {
    ...finding,
    rule: { ...rule },
    frameworks: frameworks.map((mapping) => frameworkMapping(mapping)),
    risk: { ...risk },
    controlGaps: [...controlGaps]
  };
}

function stableRule(id: string, name: string, scanner: RuleMetadata["scanner"]): RuleMetadata {
  return builtInRuleMetadata(id) ?? {
    id,
    name,
    version: BUILT_IN_RULE_VERSION,
    stability: "stable",
    scanner
  };
}

function frameworkMappingDefinition(framework: FrameworkId, id: string, name: string): FrameworkMappingDefinition {
  return {
    framework,
    id,
    name
  };
}

function frameworkMapping(definition: FrameworkMappingDefinition): FrameworkMapping {
  const catalogEntry = FRAMEWORK_CATALOG.find((entry) => entry.id === definition.framework);
  if (!catalogEntry) {
    throw new Error(`Unknown framework mapping: ${definition.framework}`);
  }

  return {
    framework: definition.framework,
    id: definition.id,
    name: definition.name,
    sourceVersion: catalogEntry.sourceVersion
  };
}
