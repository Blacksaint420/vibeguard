import type { AiBomAssetDelta, AiBomDiffResult } from "../types.ts";
import type { AiAsset, AiBom } from "./types.ts";
import { normalizeAssetName } from "./extract.ts";

export function diffAiBoms(approved: AiBom, current: AiBom): AiBomDiffResult {
  const approvedByKey = new Map(flattenAiBomAssets(approved).map((asset) => [aiAssetStableKey(asset), asset]));
  const currentByKey = new Map(flattenAiBomAssets(current).map((asset) => [aiAssetStableKey(asset), asset]));
  const added: AiBomAssetDelta[] = [];
  const removed: AiBomAssetDelta[] = [];
  const changed: AiBomAssetDelta[] = [];

  for (const [key, asset] of currentByKey) {
    const previous = approvedByKey.get(key);
    if (!previous) {
      added.push(deltaFromAsset(asset, ["added"]));
      continue;
    }
    if (previous.fingerprint !== asset.fingerprint) {
      changed.push(deltaFromAsset(asset, changesForAsset(previous, asset), previous.fingerprint));
    }
  }

  for (const [key, asset] of approvedByKey) {
    if (!currentByKey.has(key)) {
      removed.push(deltaFromAsset(asset, ["removed"]));
    }
  }

  return {
    tool: "vibeguard",
    schemaVersion: "vibeguard.aibomDiff.v1",
    generatedAt: new Date().toISOString(),
    mode: "audit",
    currentBom: {
      generatedAt: current.generatedAt,
      targetPath: current.targetPath
    },
    summary: {
      added: added.length,
      removed: removed.length,
      changed: changed.length,
      unauthorized: 0,
      blockedCapabilities: 0,
      blocking: 0
    },
    added: sortDeltas(added),
    removed: sortDeltas(removed),
    changed: sortDeltas(changed),
    violations: []
  };
}

export function flattenAiBomAssets(bom: AiBom): AiAsset[] {
  return [
    ...bom.providers,
    ...bom.models,
    ...bom.prompts,
    ...bom.agents,
    ...bom.tools,
    ...bom.mcpServers,
    ...bom.vectorStores,
    ...bom.dataStores
  ];
}

export function aiAssetStableKey(asset: AiAsset): string {
  return `${asset.kind}:${normalizeAssetName(asset.name)}:${asset.file}:${asset.line}`;
}

function deltaFromAsset(asset: AiAsset, changes: string[], previousFingerprint?: string): AiBomAssetDelta {
  return {
    assetId: asset.id,
    kind: asset.kind,
    name: asset.name,
    file: asset.file,
    line: asset.line,
    capabilities: [...asset.capabilities].sort(),
    fingerprint: asset.fingerprint,
    previousFingerprint,
    changes
  };
}

function changesForAsset(previous: AiAsset, current: AiAsset): string[] {
  const changes: string[] = [];
  if (previous.fingerprint !== current.fingerprint) changes.push("fingerprint");
  if (previous.capabilities.join(",") !== current.capabilities.join(",")) changes.push("capabilities");
  if (previous.confidence !== current.confidence) changes.push("confidence");
  if (previous.evidenceStrength !== current.evidenceStrength) changes.push("evidenceStrength");
  return changes;
}

function sortDeltas(deltas: AiBomAssetDelta[]): AiBomAssetDelta[] {
  return [...deltas].sort((left, right) => `${left.kind}:${left.file}:${left.line}:${left.name}`.localeCompare(`${right.kind}:${right.file}:${right.line}:${right.name}`));
}
