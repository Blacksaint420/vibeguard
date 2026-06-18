import { createHash } from "node:crypto";

import { isExpiredSuppressionExpiration } from "../policy.ts";
import type {
  AiBomDiffResult,
  AiGovernancePolicy,
  AiGovernanceViolation,
  Severity
} from "../types.ts";
import { diffAiBoms, flattenAiBomAssets } from "./diff.ts";
import type { AiAsset, AiBom, AiCapability } from "./types.ts";

const DRIFT_CAPABILITIES = new Set<AiCapability>(["shell", "filesystem", "database", "secret-access", "network", "mcp-tool"]);
const CRITICAL_CAPABILITIES = new Set<AiCapability>(["shell", "secret-access"]);
export function evaluateAiBomPolicy(options: {
  currentBom: AiBom;
  approvedBom?: AiBom;
  policy: AiGovernancePolicy;
  generatedAt?: string;
}): AiBomDiffResult {
  const result = options.approvedBom
    ? diffAiBoms(options.approvedBom, options.currentBom)
    : emptyDiffResult(options.currentBom);
  const violations: AiGovernanceViolation[] = [];

  for (const asset of flattenAiBomAssets(options.currentBom)) {
    collectPolicyViolations(asset, options.policy, violations);
  }

  if (options.approvedBom) {
    if (options.policy.blockOnDrift) {
      for (const delta of result.added) {
        const asset = findCurrentAsset(options.currentBom, delta.assetId);
        if (asset && !hasHighRiskCapability(asset)) {
          violations.push(driftViolation(asset, options.policy, "added"));
        }
      }

      for (const delta of result.changed) {
        const asset = findCurrentAsset(options.currentBom, delta.assetId);
        if (asset && !hasHighRiskCapability(asset)) {
          violations.push(driftViolation(asset, options.policy, "changed"));
        }
      }

      for (const delta of result.removed) {
        violations.push(removedDriftViolation(delta, options.policy));
      }
    }

    for (const delta of [...result.added, ...result.changed]) {
      const asset = findCurrentAsset(options.currentBom, delta.assetId);
      if (!asset) continue;
      for (const capability of asset.capabilities.filter((candidate) => DRIFT_CAPABILITIES.has(candidate))) {
        violations.push(violationForAsset({
          asset,
          policy: options.policy,
          ruleId: "aibom-policy/high-risk-capability-drift",
          title: "High-risk AI capability drift",
          severity: CRITICAL_CAPABILITIES.has(capability) ? "critical" : "high",
          reason: `AI asset gained or changed high-risk capability ${capability}.`,
          driftType: "blocked-capability",
          capability
        }));
      }
    }
  }

  const filteredViolations = dedupeViolations(violations)
    .filter((violation) => !hasActiveException(options.policy, violation.assetId));

  return {
    ...result,
    generatedAt: options.generatedAt ?? result.generatedAt,
    mode: options.policy.mode,
    summary: {
      ...result.summary,
      unauthorized: filteredViolations.filter((violation) => violation.driftType === "unauthorized").length,
      blockedCapabilities: filteredViolations.filter((violation) => violation.driftType === "blocked-capability").length,
      blocking: filteredViolations.filter((violation) => violation.blocking).length
    },
    violations: filteredViolations
  };
}

function collectPolicyViolations(asset: AiAsset, policy: AiGovernancePolicy, violations: AiGovernanceViolation[]): void {
  if (asset.kind === "provider") {
    if (policy.allowedProviders.length > 0 && !matchesAny(policy.allowedProviders, asset.name) && !assetAllowlisted(policy, asset)) {
      violations.push(unauthorizedViolation(asset, policy, "aibom-policy/provider-not-allowed", "Provider is not approved", "Provider is not in the AI governance allowedProviders list.", "high"));
    }
    if (matchesAny(policy.blockedProviders, asset.name)) {
      violations.push(unauthorizedViolation(asset, policy, "aibom-policy/provider-blocked", "Provider is blocked", "Provider matches the AI governance blockedProviders list.", "high"));
    }
  }

  if (asset.kind === "model") {
    if (policy.allowedModels.length > 0 && !matchesAny(policy.allowedModels, asset.name) && !assetAllowlisted(policy, asset)) {
      violations.push(unauthorizedViolation(asset, policy, "aibom-policy/model-not-allowed", "Model is not approved", "Model is not in the AI governance allowedModels list.", "medium"));
    }
    if (matchesAny(policy.blockedModels, asset.name)) {
      violations.push(unauthorizedViolation(asset, policy, "aibom-policy/model-blocked", "Model is blocked", "Model matches the AI governance blockedModels list.", "high"));
    }
  }

  if (asset.kind === "mcp-server" && policy.allowedMcpServers.length > 0 && !matchesAny(policy.allowedMcpServers, asset.name) && !assetAllowlisted(policy, asset)) {
    violations.push(unauthorizedViolation(asset, policy, "aibom-policy/mcp-server-not-allowed", "MCP server is not approved", "MCP server is not in the AI governance allowedMcpServers list.", "high"));
  }

  for (const capability of asset.capabilities) {
    if (policy.allowedCapabilities.length > 0 && !matchesAny(policy.allowedCapabilities, capability) && !assetAllowlisted(policy, asset)) {
      violations.push(violationForAsset({
        asset,
        policy,
        ruleId: "aibom-policy/capability-not-allowed",
        title: "AI capability is not approved",
        severity: CRITICAL_CAPABILITIES.has(capability) ? "critical" : "medium",
        reason: `Capability ${capability} is not in the AI governance allowedCapabilities list.`,
        driftType: "unauthorized",
        capability
      }));
    }

    if (matchesAny(policy.blockedCapabilities, capability)) {
      violations.push(violationForAsset({
        asset,
        policy,
        ruleId: "aibom-policy/capability-blocked",
        title: "AI capability is blocked",
        severity: CRITICAL_CAPABILITIES.has(capability) ? "critical" : "high",
        reason: `Capability ${capability} matches the AI governance blockedCapabilities list.`,
        driftType: "blocked-capability",
        capability
      }));
    }
  }
}

function unauthorizedViolation(
  asset: AiAsset,
  policy: AiGovernancePolicy,
  ruleId: string,
  title: string,
  reason: string,
  severity: Severity
): AiGovernanceViolation {
  return violationForAsset({
    asset,
    policy,
    ruleId,
    title,
    severity,
    reason,
    driftType: "unauthorized"
  });
}

function driftViolation(asset: AiAsset, policy: AiGovernancePolicy, driftType: "added" | "changed"): AiGovernanceViolation {
  return violationForAsset({
    asset,
    policy,
    ruleId: `aibom-policy/asset-${driftType}`,
    title: `AI asset ${driftType}`,
    severity: hasHighRiskCapability(asset) ? "high" : "medium",
    reason: `AI BOM drift detected: ${asset.kind} ${asset.name} was ${driftType}.`,
    driftType
  });
}

function removedDriftViolation(delta: AiBomDiffResult["removed"][number], policy: AiGovernancePolicy): AiGovernanceViolation {
  const id = createHash("sha256")
    .update(["aibom-policy/asset-removed", delta.assetId].join("\0"))
    .digest("hex")
    .slice(0, 12);
  return {
    id: `aibom-policy/asset-removed:${id}`,
    ruleId: "aibom-policy/asset-removed",
    title: "AI asset removed",
    severity: "low",
    assetId: delta.assetId,
    assetKind: delta.kind,
    assetName: delta.name,
    file: delta.file,
    line: delta.line,
    reason: `AI BOM drift detected: ${delta.kind} ${delta.name} was removed.`,
    driftType: "removed",
    evidenceStrength: "direct",
    evidenceSource: "approved AI BOM diff",
    blocking: isBlocking(policy, "low", "removed")
  };
}

function violationForAsset(options: {
  asset: AiAsset;
  policy: AiGovernancePolicy;
  ruleId: string;
  title: string;
  severity: Severity;
  reason: string;
  driftType: AiGovernanceViolation["driftType"];
  capability?: string;
}): AiGovernanceViolation {
  const id = createHash("sha256")
    .update([options.ruleId, options.asset.id, options.capability ?? ""].join("\0"))
    .digest("hex")
    .slice(0, 12);
  return {
    id: `${options.ruleId}:${id}`,
    ruleId: options.ruleId,
    title: options.title,
    severity: options.severity,
    assetId: options.asset.id,
    assetKind: options.asset.kind,
    assetName: options.asset.name,
    file: options.asset.file,
    line: options.asset.line,
    reason: options.reason,
    driftType: options.driftType,
    capability: options.capability,
    evidenceStrength: options.asset.evidenceStrength,
    evidenceSource: options.asset.evidenceSource,
    blocking: isBlocking(options.policy, options.severity, options.driftType)
  };
}

function isBlocking(policy: AiGovernancePolicy, severity: Severity, driftType: AiGovernanceViolation["driftType"]): boolean {
  if (policy.mode !== "block") return false;
  if (driftType === "unauthorized") return true;
  if (policy.blockOnDrift && (driftType === "added" || driftType === "removed" || driftType === "changed" || driftType === "blocked-capability")) return true;
  return policy.changeRisk.blockSeverities.includes(severity);
}

function hasActiveException(policy: AiGovernancePolicy, assetId: string): boolean {
  return policy.exceptions.some((exception) =>
    exception.assetId === assetId &&
    exception.reason.trim().length > 0 &&
    exception.reviewer.trim().length > 0 &&
    exception.expires.trim().length > 0 &&
    !isExpiredSuppressionExpiration(exception.expires)
  );
}

function assetAllowlisted(policy: AiGovernancePolicy, asset: AiAsset): boolean {
  return policy.assetAllowlist.some((selector) => {
    if (selector.kind && selector.kind !== asset.kind) return false;
    if (selector.id && selector.id !== asset.id) return false;
    if (selector.name && !patternMatches(selector.name, asset.name)) return false;
    if (selector.file && !patternMatches(selector.file, asset.file)) return false;
    if (selector.capabilities && !selector.capabilities.every((capability) => asset.capabilities.includes(capability as AiCapability))) return false;
    return true;
  });
}

function matchesAny(patterns: string[], value: string): boolean {
  return patterns.some((pattern) => patternMatches(pattern, value));
}

function findCurrentAsset(currentBom: AiBom, assetId: string): AiAsset | undefined {
  return flattenAiBomAssets(currentBom).find((candidate) => candidate.id === assetId);
}

function hasHighRiskCapability(asset: AiAsset): boolean {
  return asset.capabilities.some((capability) => DRIFT_CAPABILITIES.has(capability));
}

function patternMatches(pattern: string, value: string): boolean {
  const normalizedPattern = pattern.toLowerCase();
  const normalizedValue = value.toLowerCase();
  if (normalizedPattern === "*") return true;
  if (normalizedPattern.startsWith("*") && normalizedPattern.endsWith("*")) {
    return normalizedValue.includes(normalizedPattern.slice(1, -1));
  }
  if (normalizedPattern.startsWith("*")) return normalizedValue.endsWith(normalizedPattern.slice(1));
  if (normalizedPattern.endsWith("*")) return normalizedValue.startsWith(normalizedPattern.slice(0, -1));
  return normalizedPattern === normalizedValue;
}

function dedupeViolations(violations: AiGovernanceViolation[]): AiGovernanceViolation[] {
  return [...new Map(violations.map((violation) => [violation.id, violation])).values()]
    .sort((left, right) => `${left.file}:${left.line}:${left.ruleId}`.localeCompare(`${right.file}:${right.line}:${right.ruleId}`));
}

function emptyDiffResult(currentBom: AiBom): AiBomDiffResult {
  return {
    tool: "vibeguard",
    schemaVersion: "vibeguard.aibomDiff.v1",
    generatedAt: new Date().toISOString(),
    mode: "audit",
    currentBom: {
      generatedAt: currentBom.generatedAt,
      targetPath: currentBom.targetPath
    },
    summary: {
      added: 0,
      removed: 0,
      changed: 0,
      unauthorized: 0,
      blockedCapabilities: 0,
      blocking: 0
    },
    added: [],
    removed: [],
    changed: [],
    violations: []
  };
}
