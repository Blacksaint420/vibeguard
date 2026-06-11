import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type { Confidence, Finding, Policy, ScannerName, Severity, Suppression } from "./types.ts";

const DEFAULT_SCANNERS: ScannerName[] = [
  "code",
  "secrets",
  "dependencies",
  "docker",
  "actions",
  "sensitive-files"
];

export const DEFAULT_POLICY_TEXT = `mode: block
enabledScanners:
  - code
  - secrets
  - dependencies
  - docker
  - actions
  - sensitive-files
blockSeverities:
  - high
  - critical
include:
  - "**/*"
exclude: []
dependencyPolicy:
  vulnerable: block
  broadVersionRange: warn
secretPolicy:
  block: true
sensitiveFilePolicy:
  block: true
suppressionPolicy:
  requireReason: true
aiPrompts:
  enabled: true
suppressions: []
minConfidence: high
`;

export function defaultPolicy(): Policy {
  return {
    mode: "block",
    enabledScanners: [...DEFAULT_SCANNERS],
    blockSeverities: ["high", "critical"],
    include: ["**/*"],
    exclude: [],
    suppressions: [],
    minConfidence: "high",
    aiPrompts: { enabled: true }
  };
}

export function loadPolicy(cwd = process.cwd()): Policy {
  const path = join(cwd, "vibeguard.yml");
  if (!existsSync(path)) return defaultPolicy();
  return loadPolicyFromText(readFileSync(path, "utf8"));
}

export function loadPolicyFromText(text: string): Policy {
  const policy = defaultPolicy();
  const lines = text.split(/\r?\n/);
  let section = "";
  let currentSuppression: Suppression | undefined;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const topLevel = !line.startsWith(" ");
    if (topLevel && trimmed.endsWith(":")) {
      section = trimmed.slice(0, -1);
      continue;
    }

    if (topLevel && trimmed.includes(":")) {
      const [key, ...rest] = trimmed.split(":");
      const value = rest.join(":").trim();
      if (key === "mode" && (value === "warn" || value === "block")) policy.mode = value;
      if (key === "minConfidence" && isConfidence(value)) policy.minConfidence = value;
      continue;
    }

    if (trimmed.startsWith("- ")) {
      const value = trimmed.slice(2).replace(/^["']|["']$/g, "");
      if (section === "enabledScanners" && isScannerName(value)) policy.enabledScanners.push(value);
      if (section === "blockSeverities" && isSeverity(value)) policy.blockSeverities.push(value);
      if (section === "include") policy.include.push(value);
      if (section === "exclude") policy.exclude.push(value);
      if (section === "suppressions") {
        currentSuppression = {};
        policy.suppressions.push(currentSuppression);
        if (value.includes(":")) {
          assignSuppressionValue(currentSuppression, value);
        }
      }
      continue;
    }

    if (section === "suppressions" && currentSuppression && trimmed.includes(":")) {
      assignSuppressionValue(currentSuppression, trimmed);
    }
  }

  policy.enabledScanners = unique(policy.enabledScanners);
  policy.blockSeverities = unique(policy.blockSeverities);
  policy.include = unique(policy.include);
  policy.exclude = unique(policy.exclude);
  return policy;
}

export function applyPolicy(findings: Finding[], policy: Policy): Finding[] {
  return findings
    .filter((finding) => !isSuppressed(finding, policy.suppressions))
    .map((finding) => ({
      ...finding,
      blocking: policy.mode === "block" && policy.blockSeverities.includes(finding.severity)
    }));
}

export function isSuppressed(finding: Finding, suppressions: Suppression[]): boolean {
  return suppressions.some((suppression) => {
    if (suppression.rule && suppression.rule !== finding.ruleId && suppression.rule !== finding.id) return false;
    if (suppression.file && !globMatches(suppression.file, finding.file)) return false;
    if (suppression.line && suppression.line !== finding.line) return false;
    return true;
  });
}

export function shouldScanFile(path: string, policy: Policy): boolean {
  const included = policy.include.length === 0 || policy.include.some((pattern) => globMatches(pattern, path));
  const excluded = policy.exclude.some((pattern) => globMatches(pattern, path));
  return included && !excluded;
}

function assignSuppressionValue(suppression: Suppression, text: string): void {
  const [rawKey, ...rest] = text.split(":");
  const key = rawKey.trim();
  const value = rest.join(":").trim().replace(/^["']|["']$/g, "");
  if (key === "rule") suppression.rule = value;
  if (key === "file") suppression.file = value;
  if (key === "line") suppression.line = Number(value);
  if (key === "reason") suppression.reason = value;
}

function globMatches(pattern: string, value: string): boolean {
  if (pattern === value || pattern === "**/*") return true;
  const escaped = pattern
    .replace(/[.+^${}()|[\]\\]/g, "\\$&")
    .replace(/\*\*/g, ".*")
    .replace(/\*/g, "[^/]*");
  return new RegExp(`^${escaped}$`).test(value);
}

function isScannerName(value: string): value is ScannerName {
  return DEFAULT_SCANNERS.includes(value as ScannerName);
}

function isSeverity(value: string): value is Severity {
  return ["low", "medium", "high", "critical"].includes(value);
}

function isConfidence(value: string): value is Confidence {
  return value === "low" || value === "medium" || value === "high";
}

function unique<T>(values: T[]): T[] {
  return [...new Set(values)];
}
