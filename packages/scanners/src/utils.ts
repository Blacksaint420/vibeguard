import { createFinding } from "../../core/src/types.ts";
import { generateAiFixPrompt } from "../../core/src/prompts.ts";
import type { Confidence, Finding, OwaspLlmCategory, Severity } from "../../core/src/types.ts";

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

export function isJavaScriptFile(path: string): boolean {
  return /\.(cjs|mjs|js|jsx|ts|tsx)$/.test(path);
}

export function isPythonFile(path: string): boolean {
  return /\.py$/.test(path);
}

export function isVendoredOrGeneratedPath(path: string): boolean {
  return /(^|\/)(node_modules|dist|build|coverage|\.next|\.git|\.worktrees)(\/|$)/.test(path);
}
