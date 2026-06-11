import { readFileSync } from "node:fs";

import type { Baseline, CheckResult } from "./types.ts";

export const DEFAULT_BASELINE_PATH = "vibeguard-baseline.json";

export function createBaseline(result: CheckResult): Baseline {
  return {
    tool: "vibeguard",
    version: "0.1.0",
    generatedAt: new Date().toISOString(),
    targetPath: result.summary.targetPath,
    findings: result.findings.map((finding) => ({
      id: finding.id,
      ruleId: finding.ruleId,
      file: finding.file,
      line: finding.line
    }))
  };
}

export function serializeBaseline(baseline: Baseline): string {
  return `${JSON.stringify(baseline, null, 2)}\n`;
}

export function loadBaseline(path: string): Baseline {
  const parsed = JSON.parse(readFileSync(path, "utf8")) as Baseline;
  if (parsed.tool !== "vibeguard" || !Array.isArray(parsed.findings)) {
    throw new Error(`Invalid VibeGuard baseline: ${path}`);
  }
  return parsed;
}

export function baselineFindingIds(baseline: Baseline): string[] {
  return [...new Set(baseline.findings.map((finding) => finding.id).filter(Boolean))];
}
