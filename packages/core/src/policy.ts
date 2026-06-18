import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";

import type {
  AiGovernanceAssetSelector,
  AiGovernanceException,
  AiGovernanceMode,
  AiGovernancePolicy,
  Confidence,
  Finding,
  Policy,
  ScannerName,
  Severity,
  Suppression,
  SuppressionPolicy
} from "./types.ts";

const DEFAULT_SCANNERS: ScannerName[] = [
  "code",
  "secrets",
  "dependencies",
  "docker",
  "actions",
  "sensitive-files",
  "ai"
];

export const DEFAULT_POLICY_TEXT = `mode: warn
enabledScanners:
  - code
  - secrets
  - dependencies
  - docker
  - actions
  - sensitive-files
  - ai
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
  requireReviewer: true
  requireExpiration: true
aiPrompts:
  enabled: true
aiGovernance:
  mode: audit
  blockOnDrift: false
suppressions: []
minConfidence: high
coverage:
  requireComplete: false
  failOnUnreadable: false
`;

export function defaultPolicy(): Policy {
  return {
    mode: "warn",
    enabledScanners: [...DEFAULT_SCANNERS],
    blockSeverities: ["high", "critical"],
    include: ["**/*"],
    exclude: [],
    suppressions: [],
    suppressionPolicy: {
      requireReason: true,
      requireReviewer: true,
      requireExpiration: true
    },
    minConfidence: "high",
    coverage: {
      requireComplete: false,
      failOnUnreadable: false
    },
    aiPrompts: { enabled: true },
    aiGovernance: defaultAiGovernancePolicy()
  };
}

export function defaultAiGovernancePolicy(): AiGovernancePolicy {
  return {
    mode: "audit",
    blockOnDrift: false,
    allowedProviders: [],
    blockedProviders: [],
    allowedModels: [],
    blockedModels: [],
    allowedMcpServers: [],
    blockedCapabilities: [],
    allowedCapabilities: [],
    assetAllowlist: [],
    exceptions: [],
    changeRisk: {
      mode: "audit",
      blockSeverities: ["critical"],
      blockEvents: []
    }
  };
}

export function loadPolicy(cwd = process.cwd()): Policy {
  const path = join(cwd, "vibeguard.yml");
  if (!existsSync(path)) return defaultPolicy();
  return loadPolicyFromText(readFileSync(path, "utf8"));
}

export function loadPolicyFromText(text: string): Policy {
  if (text.trim().startsWith("{")) {
    return policyFromObject(JSON.parse(text) as Record<string, unknown>);
  }

  const policy = defaultPolicy();
  const lines = text.split(/\r?\n/);
  let section = "";
  let aiGovernanceSection = "";
  let currentSuppression: Suppression | undefined;
  let currentAssetAllowlistEntry: AiGovernanceAssetSelector | undefined;
  let currentAiGovernanceException: Partial<AiGovernanceException> | undefined;
  let hasSuppressionPolicy = false;
  let hasExplicitEnabledScanners = false;

  for (const rawLine of lines) {
    const line = rawLine.trimEnd();
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const topLevel = !line.startsWith(" ");
    const indent = line.length - line.trimStart().length;
    if (topLevel && trimmed.endsWith(":")) {
      section = trimmed.slice(0, -1);
      aiGovernanceSection = "";
      if (section === "suppressionPolicy") hasSuppressionPolicy = true;
      if (section === "enabledScanners" && !hasExplicitEnabledScanners) {
        policy.enabledScanners = [];
        hasExplicitEnabledScanners = true;
      }
      continue;
    }

    if (topLevel && trimmed.includes(":")) {
      const [key, ...rest] = trimmed.split(":");
      const value = rest.join(":").trim();
      if (key === "mode" && (value === "warn" || value === "block")) policy.mode = value;
      if (key === "minConfidence" && isConfidence(value)) policy.minConfidence = value;
      continue;
    }

    if (section === "aiGovernance") {
      if (assignAiGovernanceLine(policy.aiGovernance, trimmed, indent, {
        section: aiGovernanceSection,
        setSection: (value) => {
          aiGovernanceSection = value;
        },
        currentAsset: currentAssetAllowlistEntry,
        setCurrentAsset: (value) => {
          currentAssetAllowlistEntry = value;
        },
        currentException: currentAiGovernanceException,
        setCurrentException: (value) => {
          currentAiGovernanceException = value;
        }
      })) {
        continue;
      }
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
      continue;
    }

    if (section === "suppressionPolicy" && trimmed.includes(":")) {
      assignSuppressionPolicyValue(policy, trimmed);
    }

    if (section === "coverage" && trimmed.includes(":")) {
      assignCoveragePolicyValue(policy, trimmed);
    }
  }

  policy.enabledScanners = unique(policy.enabledScanners);
  policy.blockSeverities = unique(policy.blockSeverities);
  policy.include = unique(policy.include);
  policy.exclude = unique(policy.exclude);
  if (!hasSuppressionPolicy) {
    policy.suppressionPolicy = {
      requireReason: false,
      requireReviewer: false,
      requireExpiration: false
    };
  }
  return policy;
}

function policyFromObject(input: Record<string, unknown>): Policy {
  const policy = defaultPolicy();
  if (input.mode === "warn" || input.mode === "block") policy.mode = input.mode;
  if (isConfidence(input.minConfidence)) policy.minConfidence = input.minConfidence;
  if (Array.isArray(input.enabledScanners)) {
    policy.enabledScanners = input.enabledScanners.filter(isScannerName);
  }
  if (Array.isArray(input.blockSeverities)) {
    policy.blockSeverities = input.blockSeverities.filter(isSeverity);
  }
  if (Array.isArray(input.include)) policy.include = input.include.filter(isString);
  if (Array.isArray(input.exclude)) policy.exclude = input.exclude.filter(isString);
  if (isRecord(input.aiGovernance)) {
    policy.aiGovernance = aiGovernancePolicyFromObject(input.aiGovernance);
  }
  return policy;
}

function aiGovernancePolicyFromObject(input: Record<string, unknown>): AiGovernancePolicy {
  const policy = defaultAiGovernancePolicy();
  if (isAiGovernanceMode(input.mode)) policy.mode = input.mode;
  if (typeof input.approvedBom === "string") policy.approvedBom = input.approvedBom;
  if (typeof input.blockOnDrift === "boolean") policy.blockOnDrift = input.blockOnDrift;
  if (Array.isArray(input.allowedProviders)) policy.allowedProviders = input.allowedProviders.filter(isString);
  if (Array.isArray(input.blockedProviders)) policy.blockedProviders = input.blockedProviders.filter(isString);
  if (Array.isArray(input.allowedModels)) policy.allowedModels = input.allowedModels.filter(isString);
  if (Array.isArray(input.blockedModels)) policy.blockedModels = input.blockedModels.filter(isString);
  if (Array.isArray(input.allowedMcpServers)) policy.allowedMcpServers = input.allowedMcpServers.filter(isString);
  if (Array.isArray(input.blockedCapabilities)) policy.blockedCapabilities = input.blockedCapabilities.filter(isString);
  if (Array.isArray(input.allowedCapabilities)) policy.allowedCapabilities = input.allowedCapabilities.filter(isString);
  if (Array.isArray(input.assetAllowlist)) {
    policy.assetAllowlist = input.assetAllowlist.filter(isRecord).map((entry) => ({
      kind: stringOrUndefined(entry.kind),
      id: stringOrUndefined(entry.id),
      name: stringOrUndefined(entry.name),
      file: stringOrUndefined(entry.file),
      capabilities: Array.isArray(entry.capabilities) ? entry.capabilities.filter(isString) : undefined
    }));
  }
  if (Array.isArray(input.exceptions)) {
    policy.exceptions = input.exceptions.filter(isRecord).flatMap((entry) => {
      const exception = governanceExceptionFromObject(entry);
      return exception ? [exception] : [];
    });
  }
  if (isRecord(input.changeRisk)) {
    if (isAiGovernanceMode(input.changeRisk.mode)) policy.changeRisk.mode = input.changeRisk.mode;
    if (Array.isArray(input.changeRisk.blockSeverities)) policy.changeRisk.blockSeverities = input.changeRisk.blockSeverities.filter(isSeverity);
    if (Array.isArray(input.changeRisk.blockEvents)) policy.changeRisk.blockEvents = input.changeRisk.blockEvents.filter(isString);
  }
  return policy;
}

export function applyPolicy(findings: Finding[], policy: Policy): Finding[] {
  return findings
    .filter((finding) => !isSuppressed(finding, policy.suppressions, policy.suppressionPolicy))
    .map((finding) => ({
      ...finding,
      blocking: policy.mode === "block" && policy.blockSeverities.includes(finding.severity)
    }));
}

export function isSuppressed(
  finding: Finding,
  suppressions: Suppression[],
  suppressionPolicy: SuppressionPolicy = defaultPolicy().suppressionPolicy
): boolean {
  return suppressions.some((suppression) => {
    if (!isValidSuppression(suppression, suppressionPolicy)) return false;
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
  if (key === "reviewer") suppression.reviewer = value;
  if (key === "expires") suppression.expires = value;
}

function assignSuppressionPolicyValue(policy: Policy, text: string): void {
  const [rawKey, ...rest] = text.split(":");
  const key = rawKey.trim();
  const value = parseBoolean(rest.join(":").trim());
  if (value === undefined) return;
  if (key === "requireReason") policy.suppressionPolicy.requireReason = value;
  if (key === "requireReviewer") policy.suppressionPolicy.requireReviewer = value;
  if (key === "requireExpiration") policy.suppressionPolicy.requireExpiration = value;
}

function assignCoveragePolicyValue(policy: Policy, text: string): void {
  const [rawKey, ...rest] = text.split(":");
  const key = rawKey.trim();
  const rawValue = rest.join(":").trim();
  const booleanValue = parseBoolean(rawValue);
  if (key === "requireComplete" && booleanValue !== undefined) policy.coverage.requireComplete = booleanValue;
  if (key === "failOnUnreadable" && booleanValue !== undefined) policy.coverage.failOnUnreadable = booleanValue;
  if (key === "maxFiles" && Number.isInteger(Number(rawValue)) && Number(rawValue) > 0) policy.coverage.maxFiles = Number(rawValue);
  if (key === "maxFileBytes" && Number.isInteger(Number(rawValue)) && Number(rawValue) > 0) policy.coverage.maxFileBytes = Number(rawValue);
}

function assignAiGovernanceLine(
  policy: AiGovernancePolicy,
  trimmed: string,
  indent: number,
  state: {
    section: string;
    setSection(value: string): void;
    currentAsset?: AiGovernanceAssetSelector;
    setCurrentAsset(value: AiGovernanceAssetSelector | undefined): void;
    currentException?: Partial<AiGovernanceException>;
    setCurrentException(value: Partial<AiGovernanceException> | undefined): void;
  }
): boolean {
  if (indent === 2 && trimmed.endsWith(":")) {
    state.setSection(trimmed.slice(0, -1));
    state.setCurrentAsset(undefined);
    state.setCurrentException(undefined);
    return true;
  }

  if (indent === 2 && trimmed.includes(":")) {
    const [key, value] = splitKeyValue(trimmed);
    state.setSection("");
    if (key === "mode" && isAiGovernanceMode(value)) policy.mode = value;
    if (key === "approvedBom") policy.approvedBom = unquote(value);
    if (key === "blockOnDrift") {
      const parsed = parseBoolean(value);
      if (parsed !== undefined) policy.blockOnDrift = parsed;
    }
    return true;
  }

  if (indent === 4 && trimmed.startsWith("- ")) {
    const value = unquote(trimmed.slice(2));
    if (state.section === "allowedProviders") policy.allowedProviders.push(value);
    if (state.section === "blockedProviders") policy.blockedProviders.push(value);
    if (state.section === "allowedModels") policy.allowedModels.push(value);
    if (state.section === "blockedModels") policy.blockedModels.push(value);
    if (state.section === "allowedMcpServers") policy.allowedMcpServers.push(value);
    if (state.section === "blockedCapabilities") policy.blockedCapabilities.push(value);
    if (state.section === "allowedCapabilities") policy.allowedCapabilities.push(value);
    if (state.section === "assetAllowlist") {
      const entry: AiGovernanceAssetSelector = {};
      state.setCurrentAsset(entry);
      policy.assetAllowlist.push(entry);
      if (value.includes(":")) assignAssetSelectorValue(entry, value);
    }
    if (state.section === "exceptions") {
      const exception: Partial<AiGovernanceException> = {};
      state.setCurrentException(exception);
      policy.exceptions.push(exception as AiGovernanceException);
      if (value.includes(":")) assignGovernanceExceptionValue(exception, value);
    }
    if (state.section === "blockSeverities" && isSeverity(value)) policy.changeRisk.blockSeverities.push(value);
    if (state.section === "blockEvents") policy.changeRisk.blockEvents.push(value);
    return true;
  }

  if (
    indent === 4 &&
    trimmed.endsWith(":") &&
    (state.section === "changeRisk" || trimmed === "blockSeverities:" || trimmed === "blockEvents:")
  ) {
    const nestedSection = trimmed.slice(0, -1);
    state.setSection(nestedSection);
    if (nestedSection === "blockSeverities") policy.changeRisk.blockSeverities = [];
    if (nestedSection === "blockEvents") policy.changeRisk.blockEvents = [];
    return true;
  }

  if (indent === 4 && state.section === "changeRisk" && trimmed.includes(":")) {
    const [key, value] = splitKeyValue(trimmed);
    if (key === "mode" && isAiGovernanceMode(value)) policy.changeRisk.mode = value;
    return true;
  }

  if (indent === 6 && trimmed.startsWith("- ")) {
    const value = unquote(trimmed.slice(2));
    if (state.section === "blockSeverities" && isSeverity(value)) policy.changeRisk.blockSeverities.push(value);
    if (state.section === "blockEvents") policy.changeRisk.blockEvents.push(value);
    return true;
  }

  if (indent === 6 && state.currentAsset && trimmed.includes(":")) {
    assignAssetSelectorValue(state.currentAsset, trimmed);
    return true;
  }

  if (indent === 6 && state.currentException && trimmed.includes(":")) {
    assignGovernanceExceptionValue(state.currentException, trimmed);
    return true;
  }

  return false;
}

function assignAssetSelectorValue(selector: AiGovernanceAssetSelector, text: string): void {
  const [key, value] = splitKeyValue(text);
  if (key === "kind") selector.kind = unquote(value);
  if (key === "id") selector.id = unquote(value);
  if (key === "name") selector.name = unquote(value);
  if (key === "file") selector.file = unquote(value);
  if (key === "capabilities") selector.capabilities = splitCsv(value);
}

function assignGovernanceExceptionValue(exception: Partial<AiGovernanceException>, text: string): void {
  const [key, value] = splitKeyValue(text);
  if (key === "assetId") exception.assetId = unquote(value);
  if (key === "reason") exception.reason = unquote(value);
  if (key === "reviewer") exception.reviewer = unquote(value);
  if (key === "expires") exception.expires = unquote(value);
}

function governanceExceptionFromObject(input: Record<string, unknown>): AiGovernanceException | undefined {
  if (
    typeof input.assetId !== "string" ||
    typeof input.reason !== "string" ||
    typeof input.reviewer !== "string" ||
    typeof input.expires !== "string"
  ) {
    return undefined;
  }
  return {
    assetId: input.assetId,
    reason: input.reason,
    reviewer: input.reviewer,
    expires: input.expires
  };
}

function isValidSuppression(suppression: Suppression, suppressionPolicy: SuppressionPolicy): boolean {
  if (suppressionPolicy.requireReason && !suppression.reason?.trim()) return false;
  if (suppressionPolicy.requireReviewer && !suppression.reviewer?.trim()) return false;
  if (suppressionPolicy.requireExpiration && !suppression.expires?.trim()) return false;
  if (suppression.expires && isExpiredSuppressionExpiration(suppression.expires)) return false;
  return true;
}

export function isExpiredSuppressionExpiration(expires: string): boolean {
  const timestamp = parseExpirationEnd(expires);
  return timestamp === undefined || timestamp < Date.now();
}

export function isValidSuppressionExpiration(expires: string): boolean {
  return parseExpirationEnd(expires) !== undefined;
}

function parseExpirationEnd(expires: string): number | undefined {
  const match = /^(\d{4})-(\d{2})-(\d{2})$/.exec(expires);
  if (!match) return undefined;
  const year = Number(match[1]);
  const month = Number(match[2]);
  const day = Number(match[3]);
  const timestamp = Date.UTC(year, month - 1, day, 23, 59, 59, 999);
  const parsed = new Date(timestamp);
  if (
    parsed.getUTCFullYear() !== year ||
    parsed.getUTCMonth() !== month - 1 ||
    parsed.getUTCDate() !== day
  ) {
    return undefined;
  }
  return timestamp;
}

function parseBoolean(value: string): boolean | undefined {
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

function splitKeyValue(text: string): [string, string] {
  const [rawKey, ...rest] = text.split(":");
  return [rawKey.trim(), rest.join(":").trim()];
}

function unquote(value: string): string {
  return value.trim().replace(/^["']|["']$/g, "");
}

function splitCsv(value: string): string[] {
  const trimmed = unquote(value);
  if (trimmed.startsWith("[") && trimmed.endsWith("]")) {
    return trimmed.slice(1, -1).split(",").map((entry) => unquote(entry)).filter(Boolean);
  }
  return trimmed.split(",").map((entry) => unquote(entry)).filter(Boolean);
}

function isAiGovernanceMode(value: unknown): value is AiGovernanceMode {
  return value === "audit" || value === "block";
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function stringOrUndefined(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
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
