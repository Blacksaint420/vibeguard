import { createFinding } from "./types.ts";
import { FRAMEWORK_CATALOG } from "./frameworks/catalog.ts";
import { enrichFindingWithEnterpriseContext } from "./frameworks/crosswalk.ts";
import { builtInRuleDefinition } from "./rules.ts";

type RuleExplanation = {
  ruleId: string;
  title: string;
  why?: string;
  fix?: string;
};

export function explainRule(id: string): string | undefined {
  const builtInRule = builtInRuleDefinition(id);
  const rule = builtInRule ? {
    ruleId: builtInRule.id,
    title: builtInRule.name,
    why: builtInRule.why,
    fix: builtInRule.fix
  } : undefined;
  if (!rule) return undefined;
  const enterpriseContext = explainEnterpriseContext(rule);
  return [
    `${rule.ruleId}: ${rule.title}`,
    "",
    `Why it matters: ${rule.why ?? genericWhy(rule.title)}`,
    `Suggested fix: ${rule.fix ?? genericFix()}`,
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
    why: rule.why ?? genericWhy(rule.title),
    suggestedFix: rule.fix ?? genericFix(),
    aiFixPrompt: "",
    testSuggestion: "",
    blocking: false
  }));
}

function formatFrameworkMappings(finding: ReturnType<typeof explainEnterpriseContext>): string[] {
  if (!finding.frameworks.length) return ["- No framework mapping"];

  return finding.frameworks.map((mapping) => {
    const frameworkName = FRAMEWORK_CATALOG.find((framework) => framework.id === mapping.framework)?.name ?? mapping.framework;
    return `- ${frameworkName}: ${mapping.id} - ${mapping.name}`;
  });
}

function genericWhy(title: string): string {
  return `${title} is a first-party VibeGuard technical finding that can create security or operational risk if left unreviewed.`;
}

function genericFix(): string {
  return "Review the finding evidence, apply the scanner recommendation, and add a regression test or policy check for the control.";
}
