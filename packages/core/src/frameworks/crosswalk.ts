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
  },
  "ai-output-json-without-schema-validation": aiSecurityContext(
    "ai-output-json-without-schema-validation",
    "LLM JSON output parsed without schema validation",
    "AI output handling",
    "high",
    "high",
    "high",
    "engineering",
    ["schema validation", "output handling", "structured outputs"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM05:2025", "Improper Output Handling"),
      frameworkMappingDefinition("nist-ai-rmf", "MEASURE", "Analyze and assess AI risks"),
      frameworkMappingDefinition("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
    ]
  ),
  "ai-llm-call-without-timeout": aiSecurityContext(
    "ai-llm-call-without-timeout",
    "LLM call has no visible timeout or abort signal",
    "AI resource consumption",
    "medium",
    "high",
    "high",
    "platform",
    ["timeouts", "availability controls", "resource quotas"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM10:2025", "Unbounded Consumption"),
      frameworkMappingDefinition("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMappingDefinition("google-saif", "secure-by-default", "Secure-by-default deployment")
    ]
  ),
  "ai-llm-call-without-rate-limit": aiSecurityContext(
    "ai-llm-call-without-rate-limit",
    "User-facing LLM endpoint has no visible rate limit or quota",
    "AI resource consumption",
    "medium",
    "high",
    "high",
    "platform",
    ["rate limiting", "quota enforcement", "abuse prevention"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM10:2025", "Unbounded Consumption"),
      frameworkMappingDefinition("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMappingDefinition("google-saif", "secure-by-default", "Secure-by-default deployment")
    ]
  ),
  "ai-llm-call-without-cost-tracking": aiSecurityContext(
    "ai-llm-call-without-cost-tracking",
    "User-triggered LLM call lacks visible usage or cost tracking",
    "AI resource consumption",
    "medium",
    "medium",
    "medium",
    "platform",
    ["usage metering", "cost tracking", "quota enforcement"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM10:2025", "Unbounded Consumption"),
      frameworkMappingDefinition("nist-ai-rmf", "MEASURE", "Analyze and assess AI risks"),
      frameworkMappingDefinition("google-saif", "secure-by-default", "Secure-by-default deployment")
    ]
  ),
  "ai-prompt-template-interpolates-user-input": aiSecurityContext(
    "ai-prompt-template-interpolates-user-input",
    "Prompt template interpolates user-controlled input",
    "Prompt injection exposure",
    "high",
    "high",
    "high",
    "engineering",
    ["prompt separation", "input delimiting", "instruction hierarchy"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM01:2025", "Prompt Injection"),
      frameworkMappingDefinition("nist-ai-rmf", "MAP", "Map AI context and risks"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0051", "LLM Prompt Injection"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
    ]
  ),
  "ai-system-prompt-logged": aiSecurityContext(
    "ai-system-prompt-logged",
    "System or developer prompt is logged",
    "Prompt confidentiality",
    "medium",
    "high",
    "high",
    "security",
    ["prompt confidentiality", "telemetry redaction", "sensitive data handling"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM02:2025", "Sensitive Information Disclosure"),
      frameworkMappingDefinition("owasp-llm-2025", "LLM07:2025", "System Prompt Leakage"),
      frameworkMappingDefinition("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMappingDefinition("google-saif", "secure-secrets", "Secure secrets and credentials")
    ]
  ),
  "ai-rag-upsert-untrusted-content": aiSecurityContext(
    "ai-rag-upsert-untrusted-content",
    "Untrusted content is inserted into a vector store",
    "RAG data integrity",
    "high",
    "high",
    "high",
    "engineering",
    ["content provenance", "moderation", "trusted ingestion"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM04:2025", "Data and Model Poisoning"),
      frameworkMappingDefinition("nist-ai-rmf", "MAP", "Map AI context and risks"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0054", "LLM Data Leakage"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
    ]
  ),
  "ai-rag-client-controlled-filter": aiSecurityContext(
    "ai-rag-client-controlled-filter",
    "RAG query uses client-controlled filter or namespace",
    "RAG data exposure",
    "high",
    "high",
    "high",
    "engineering",
    ["retrieval authorization", "tenant isolation", "server-side filters"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM08:2025", "Vector and Embedding Weaknesses"),
      frameworkMappingDefinition("nist-ai-rmf", "MAP", "Map AI context and risks"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0054", "LLM Data Leakage"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
    ]
  ),
  "ai-mcp-config-dangerous-server": aiSecurityContext(
    "ai-mcp-config-dangerous-server",
    "MCP config exposes dangerous server without scope metadata",
    "Agentic AI excessive agency",
    "high",
    "critical",
    "critical",
    "engineering",
    ["MCP scope", "tool approval", "runtime containment"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM06:2025", "Excessive Agency"),
      frameworkMappingDefinition("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0051", "LLM Prompt Injection"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
    ]
  ),
  "ai-tool-broad-input-schema": aiSecurityContext(
    "ai-tool-broad-input-schema",
    "Agent tool accepts broad free-form input",
    "Agentic AI excessive agency",
    "high",
    "high",
    "high",
    "engineering",
    ["tool schema constraints", "least privilege", "argument allowlisting"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM06:2025", "Excessive Agency"),
      frameworkMappingDefinition("nist-ai-rmf", "MANAGE", "Prioritize and respond to AI risks"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0051", "LLM Prompt Injection"),
      frameworkMappingDefinition("google-saif", "input-output-controls", "Input and output controls")
    ]
  ),
  "ai-model-revision-unpinned": aiSecurityContext(
    "ai-model-revision-unpinned",
    "Model artifact revision is not pinned",
    "AI supply chain",
    "high",
    "high",
    "high",
    "security",
    ["model provenance", "artifact pinning", "supply chain review"],
    [
      frameworkMappingDefinition("owasp-llm-2025", "LLM03:2025", "Supply Chain"),
      frameworkMappingDefinition("nist-ai-rmf", "GOVERN", "Govern AI risk management"),
      frameworkMappingDefinition("mitre-atlas", "AML.T0010", "Acquire ML Artifacts"),
      frameworkMappingDefinition("google-saif", "secure-supply-chain", "Secure supply chain")
    ]
  ),
  "agent-capability-shell-without-approval": agentCapabilityContext(
    "agent-capability-shell-without-approval",
    "Agent can reach shell execution",
    "command execution"
  ),
  "agent-capability-filesystem-access": agentCapabilityContext(
    "agent-capability-filesystem-access",
    "Agent can reach filesystem access",
    "filesystem access"
  ),
  "agent-capability-database-access": agentCapabilityContext(
    "agent-capability-database-access",
    "Agent can reach database access",
    "database access"
  ),
  "agent-capability-secret-access": agentCapabilityContext(
    "agent-capability-secret-access",
    "Agent can reach secret-bearing configuration",
    "secret access"
  ),
  "agent-capability-mcp-tool-access": agentCapabilityContext(
    "agent-capability-mcp-tool-access",
    "Agent can reach MCP tool capability",
    "MCP tool access"
  )
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

function aiSecurityContext(
  id: string,
  name: string,
  category: string,
  likelihood: RuleEnterpriseContextDefinition["risk"]["likelihood"],
  impact: RuleEnterpriseContextDefinition["risk"]["impact"],
  severity: RuleEnterpriseContextDefinition["risk"]["severity"],
  controlOwner: RuleEnterpriseContextDefinition["risk"]["controlOwner"],
  controlGaps: string[],
  frameworks: FrameworkMappingDefinition[]
): RuleEnterpriseContextDefinition {
  return {
    rule: stableRule(id, name, "ai"),
    frameworks,
    risk: {
      category,
      likelihood,
      impact,
      severity,
      controlOwner
    },
    controlGaps
  };
}

function agentCapabilityContext(id: string, name: string, gap: string): RuleEnterpriseContextDefinition {
  return {
    rule: stableRule(id, name, "ai"),
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
    controlGaps: [gap, "tool approval", "least privilege", "runtime containment"]
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
