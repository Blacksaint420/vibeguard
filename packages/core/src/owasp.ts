import type { Finding, OwaspLlmCategory, OwaspLlmCategoryId } from "./types.ts";

export const OWASP_LLM_2025: Record<OwaspLlmCategoryId, OwaspLlmCategory> = {
  "LLM01:2025": { id: "LLM01:2025", name: "Prompt Injection" },
  "LLM02:2025": { id: "LLM02:2025", name: "Sensitive Information Disclosure" },
  "LLM03:2025": { id: "LLM03:2025", name: "Supply Chain" },
  "LLM04:2025": { id: "LLM04:2025", name: "Data and Model Poisoning" },
  "LLM05:2025": { id: "LLM05:2025", name: "Improper Output Handling" },
  "LLM06:2025": { id: "LLM06:2025", name: "Excessive Agency" },
  "LLM07:2025": { id: "LLM07:2025", name: "System Prompt Leakage" },
  "LLM08:2025": { id: "LLM08:2025", name: "Vector and Embedding Weaknesses" },
  "LLM09:2025": { id: "LLM09:2025", name: "Misinformation" },
  "LLM10:2025": { id: "LLM10:2025", name: "Unbounded Consumption" }
};

export function owaspCategory(id: OwaspLlmCategoryId): OwaspLlmCategory {
  return OWASP_LLM_2025[id];
}

export function summarizeOwaspFindings(findings: Finding[]): Array<{ id: OwaspLlmCategoryId; name: string; count: number; blocking: number }> {
  const counts = new Map<OwaspLlmCategoryId, { count: number; blocking: number }>();
  for (const finding of findings) {
    if (!finding.owasp) continue;
    const current = counts.get(finding.owasp.id) ?? { count: 0, blocking: 0 };
    current.count += 1;
    if (finding.blocking) current.blocking += 1;
    counts.set(finding.owasp.id, current);
  }

  return [...counts.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([id, value]) => ({
      id,
      name: OWASP_LLM_2025[id].name,
      count: value.count,
      blocking: value.blocking
    }));
}
