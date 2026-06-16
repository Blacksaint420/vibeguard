import type { Finding, FrameworkId, RiskLevel } from "./types.ts";

export const UNMAPPED_GRC_RISK_CATEGORY = "Unmapped technical finding";

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
    const category = finding.risk?.category ?? UNMAPPED_GRC_RISK_CATEGORY;
    const severity = finding.risk?.severity ?? finding.severity;
    const current = byCategory.get(category) ?? { count: 0, highestSeverity: "low" };
    current.count += 1;
    current.highestSeverity = higherRisk(current.highestSeverity, severity);
    byCategory.set(category, current);

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
