import { createFinding } from "./types.ts";
import { FRAMEWORK_CATALOG } from "./frameworks/catalog.ts";
import { enrichFindingWithEnterpriseContext } from "./frameworks/crosswalk.ts";

const BUILT_IN_RULE_VERSION = "2026.06.11";

type RuleExplanation = {
  ruleId: string;
  title: string;
  why: string;
  fix: string;
};

const RULES: RuleExplanation[] = [
  {
    ruleId: "js-eval",
    title: "JavaScript eval usage",
    why: "Dynamic code execution can run attacker-controlled input and bypass normal review boundaries.",
    fix: "Replace eval with explicit parsing, schema validation, or a narrow command dispatch table."
  },
  {
    ruleId: "secret-github-token",
    title: "GitHub token in changed code",
    why: "Committed access tokens can be harvested from git history and used outside your environment.",
    fix: "Revoke the token, move secrets to a secret manager or environment variable, and rotate credentials."
  },
  {
    ruleId: "dep-broad-version-range",
    title: "Broad dependency version range",
    why: "Broad ranges can pull unreviewed code in future installs.",
    fix: "Pin the dependency or use a narrowly reviewed range plus lockfile review."
  },
  {
    ruleId: "docker-base-latest",
    title: "Docker base image uses latest",
    why: "The latest tag is mutable, so builds can change without a code review.",
    fix: "Pin the image to an explicit version or immutable digest."
  },
  {
    ruleId: "gha-mutable-action-ref",
    title: "GitHub Action uses mutable reference",
    why: "Mutable action refs can change after review and alter CI behavior.",
    fix: "Pin actions to a full commit SHA."
  }
];

export function explainRule(id: string): string | undefined {
  const rule = RULES.find((candidate) => id === candidate.ruleId || id.startsWith(`${candidate.ruleId}:`));
  if (!rule) return undefined;
  const enterpriseContext = builtInEnterpriseContext(rule);
  return [
    `${rule.ruleId}: ${rule.title}`,
    "",
    `Why it matters: ${rule.why}`,
    `Suggested fix: ${rule.fix}`,
    "",
    `Rule version: ${enterpriseContext.rule?.version ?? "unknown"}`,
    `Rule stability: ${enterpriseContext.rule?.stability ?? "unknown"}`,
    `Risk category: ${enterpriseContext.risk?.category ?? "Unmapped technical finding"}`,
    "Framework mappings:",
    ...formatFrameworkMappings(enterpriseContext)
  ].join("\n");
}

function explainEnterpriseContext(rule: RuleExplanation) {
  return enrichFindingWithEnterpriseContext(createFinding({
    id: `explain:${rule.ruleId}`,
    ruleId: rule.ruleId,
    title: rule.title,
    severity: "medium",
    confidence: "high",
    riskScore: 0,
    file: "<explain>",
    line: 0,
    snippet: "",
    why: rule.why,
    suggestedFix: rule.fix,
    aiFixPrompt: "",
    testSuggestion: "",
    blocking: false
  }));
}

function builtInEnterpriseContext(rule: RuleExplanation): ReturnType<typeof explainEnterpriseContext> {
  const context = explainEnterpriseContext(rule);
  if (context.rule?.stability !== "custom") return context;

  return {
    ...context,
    rule: {
      id: rule.ruleId,
      name: rule.title,
      version: BUILT_IN_RULE_VERSION,
      stability: "stable"
    }
  };
}

function formatFrameworkMappings(finding: ReturnType<typeof explainEnterpriseContext>): string[] {
  if (!finding.frameworks.length) return ["- No framework mapping"];

  return finding.frameworks.map((mapping) => {
    const frameworkName = FRAMEWORK_CATALOG.find((framework) => framework.id === mapping.framework)?.name ?? mapping.framework;
    return `- ${frameworkName}: ${mapping.id} - ${mapping.name}`;
  });
}
