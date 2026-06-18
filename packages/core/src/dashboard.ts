import type { AgentCapabilityGraph, AiBom } from "./aibom/index.ts";
import type { AiBomDiffResult, CheckResult } from "./types.ts";

export type DashboardSectionStatus = "available" | "missing" | "invalid";

export type DashboardArtifactRef = {
  name: string;
  path?: string;
  schemaVersion?: string;
  sha256?: string;
  status: DashboardSectionStatus;
  message?: string;
};

export type DashboardCoverageSummary = {
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  filesExcludedByPolicy: number;
  filesSkippedBinary: number;
  filesSkippedOversized: number;
  filesUnreadable: number;
  fileLimitReached: boolean;
  coveragePercent: number;
  coverageStatus: string;
};

export type DashboardSummary = {
  posture: "pass" | "review" | "blocked" | "unknown";
  generatedAt: string;
  targetPath?: string;
  blocking: number;
  findings: number;
  aiAssets: number;
  highRiskCapabilities: string[];
  changeRiskEvents: number;
  governanceViolations: number;
  coverage?: DashboardCoverageSummary;
};

export type DashboardData = {
  tool: "vibeguard";
  schemaVersion: "vibeguard.dashboard.v1";
  generatedAt: string;
  summary: DashboardSummary;
  artifacts: DashboardArtifactRef[];
  aiBom?: AiBom;
  aiBomDiff?: AiBomDiffResult;
  riskReport?: CheckResult | Record<string, unknown>;
  agentGraph?: AgentCapabilityGraph;
  changeRisk?: Record<string, unknown>;
  suppressions?: unknown[];
  grcMappings?: Record<string, unknown>;
  warnings: string[];
  dataHandling: {
    localFirst: true;
    uploadsByDefault: false;
    externalResources: false;
  };
};

export type DashboardArtifactInputs = {
  manifest?: unknown;
  aiBom?: unknown;
  aiBomDiff?: unknown;
  riskReport?: unknown;
  agentGraph?: unknown;
  changeRisk?: unknown;
  suppressions?: unknown;
  grcMappings?: unknown;
  artifactRefs?: DashboardArtifactRef[];
  generatedAt?: string;
};

type NormalizedInputs = {
  manifest?: Record<string, unknown>;
  aiBom?: AiBom;
  aiBomDiff?: AiBomDiffResult;
  riskReport?: DashboardData["riskReport"];
  agentGraph?: AgentCapabilityGraph;
  changeRisk?: Record<string, unknown>;
  suppressions?: unknown[];
  grcMappings?: Record<string, unknown>;
};

export function buildDashboardData(inputs: DashboardArtifactInputs): DashboardData {
  const generatedAt = inputs.generatedAt ?? new Date().toISOString();
  const normalized = normalizeInputs(inputs);
  const artifacts = normalizeArtifactRefs(inputs, normalized);
  const warnings = dashboardWarnings(inputs, normalized, artifacts);

  if (!hasRecognizableArtifact(normalized)) {
    throw new Error("No recognizable VibeGuard artifacts were provided for dashboard generation.");
  }

  return {
    tool: "vibeguard",
    schemaVersion: "vibeguard.dashboard.v1",
    generatedAt,
    summary: deriveDashboardSummary({ ...normalized, generatedAt }),
    artifacts,
    aiBom: normalized.aiBom,
    aiBomDiff: normalized.aiBomDiff,
    riskReport: normalized.riskReport,
    agentGraph: normalized.agentGraph,
    changeRisk: normalized.changeRisk,
    suppressions: normalized.suppressions,
    grcMappings: normalized.grcMappings,
    warnings,
    dataHandling: {
      localFirst: true,
      uploadsByDefault: false,
      externalResources: false
    }
  };
}

function normalizeInputs(inputs: DashboardArtifactInputs): NormalizedInputs {
  return {
    manifest: isObject(inputs.manifest) ? inputs.manifest : undefined,
    aiBom: isAiBom(inputs.aiBom) ? inputs.aiBom : undefined,
    aiBomDiff: normalizeAiBomDiff(inputs.aiBomDiff),
    riskReport: isObject(inputs.riskReport) ? inputs.riskReport as DashboardData["riskReport"] : undefined,
    agentGraph: isAgentGraph(inputs.agentGraph) ? inputs.agentGraph : undefined,
    changeRisk: isObject(inputs.changeRisk) ? inputs.changeRisk as Record<string, unknown> : undefined,
    suppressions: Array.isArray(inputs.suppressions) ? inputs.suppressions : undefined,
    grcMappings: isObject(inputs.grcMappings) ? inputs.grcMappings : undefined
  };
}

function deriveDashboardSummary(inputs: NormalizedInputs & { generatedAt: string }): DashboardSummary {
  const riskSummary = isObject(inputs.riskReport?.summary) ? inputs.riskReport.summary : undefined;
  const changeRiskSummary = isObject(inputs.changeRisk?.summary) ? inputs.changeRisk.summary : undefined;
  const embeddedGovernance = governanceFromRiskReport(inputs.riskReport);
  const riskBlockingIncludesGovernance = typeof riskSummary?.blocking === "number" && Boolean(embeddedGovernance);
  const governanceForSummary = inputs.aiBomDiff ?? embeddedGovernance;
  const governanceBlocking = riskBlockingIncludesGovernance ? 0 : numberValue(governanceForSummary?.summary.blocking);
  const blocking = numberValue(riskSummary?.blocking) + governanceBlocking + numberValue(changeRiskSummary?.blocking);
  const findings = numberValue(riskSummary?.findings);
  const aiAssets = inputs.aiBom ? sumAiAssets(inputs.aiBom) : 0;
  const changeRiskEvents = numberValue(changeRiskSummary?.events, Array.isArray(inputs.changeRisk?.events) ? inputs.changeRisk.events.length : 0);
  const governanceViolations = governanceForSummary?.violations.length ?? 0;
  const posture = derivePosture({ blocking, findings, governanceViolations, changeRiskEvents, riskReport: inputs.riskReport });

  return {
    posture,
    generatedAt: inputs.generatedAt,
    targetPath: targetPathFromArtifacts(inputs),
    blocking,
    findings,
    aiAssets,
    highRiskCapabilities: inputs.aiBom?.summary.highRiskCapabilities.filter(isString) ?? [],
    changeRiskEvents,
    governanceViolations,
    coverage: coverageFromRiskReport(inputs.riskReport)
  };
}

function normalizeArtifactRefs(inputs: DashboardArtifactInputs, normalized: NormalizedInputs): DashboardArtifactRef[] {
  const artifactRefs = [...(inputs.artifactRefs ?? [])];
  const names: Array<keyof Pick<DashboardArtifactInputs, "manifest" | "aiBom" | "aiBomDiff" | "riskReport" | "agentGraph" | "changeRisk" | "suppressions" | "grcMappings">> = [
    "manifest",
    "aiBom",
    "aiBomDiff",
    "riskReport",
    "agentGraph",
    "changeRisk",
    "suppressions",
    "grcMappings"
  ];

  for (const name of names) {
    if (inputs[name] === undefined || artifactRefs.some((artifact) => artifact.name === name)) continue;
    artifactRefs.push({
      name,
      schemaVersion: schemaVersionFor(inputs[name]),
      status: normalized[name] === undefined ? "invalid" : "available",
      message: normalized[name] === undefined ? invalidMessageFor(name) : undefined
    });
  }

  return artifactRefs;
}

function dashboardWarnings(inputs: DashboardArtifactInputs, normalized: NormalizedInputs, artifacts: DashboardArtifactRef[]): string[] {
  const warnings: string[] = [];
  for (const artifact of artifacts.filter((item) => item.status === "invalid")) {
    warnings.push(artifact.message ?? `${displayNameFor(artifact.name)} artifact is invalid or not recognized.`);
  }
  for (const artifact of artifacts.filter((item) => item.status === "missing")) {
    warnings.push(artifact.message ?? `${displayNameFor(artifact.name)} artifact is missing.`);
  }

  if (inputs.manifest === undefined && !normalized.manifest) warnings.push("Evidence-pack manifest is missing. Dashboards can still render supplied artifacts without a manifest.");
  if (inputs.aiBom === undefined && !normalized.aiBom) warnings.push("AI BOM artifact is missing. Run: vibeguard aibom . --format aibom-json --output aibom.json");
  if (inputs.aiBomDiff === undefined && !normalized.aiBomDiff) warnings.push("AI BOM governance diff is missing. Run: vibeguard aibom diff --approved-aibom .vibeguard/approved-aibom.json --format json");
  if (inputs.riskReport === undefined && !normalized.riskReport) warnings.push("Risk report artifact is missing. Run: vibeguard check . --format json --output sast.json");
  if (inputs.agentGraph === undefined && !normalized.agentGraph) warnings.push("Agent capability graph is missing. Run: vibeguard graph . --format graph-json --output agent-graph.json");
  if (inputs.changeRisk === undefined && !normalized.changeRisk) warnings.push("AI change-risk artifact is missing. Run: vibeguard change-risk . --format json --output change-risk.json");
  if (inputs.suppressions === undefined && !normalized.suppressions) warnings.push("Suppressions artifact is missing; accepted-risk visibility will be unavailable.");
  if (inputs.grcMappings === undefined && !normalized.grcMappings) warnings.push("GRC mappings artifact is missing; enterprise mapping details may be limited.");
  return warnings;
}

function hasRecognizableArtifact(inputs: NormalizedInputs): boolean {
  return Boolean(
    inputs.manifest ||
    inputs.aiBom ||
    inputs.aiBomDiff ||
    inputs.riskReport ||
    inputs.agentGraph ||
    inputs.changeRisk ||
    inputs.suppressions ||
    inputs.grcMappings
  );
}

function derivePosture(inputs: {
  blocking: number;
  findings: number;
  governanceViolations: number;
  changeRiskEvents: number;
  riskReport?: DashboardData["riskReport"];
}): DashboardSummary["posture"] {
  if (inputs.blocking > 0) return "blocked";
  if (inputs.findings > 0 || inputs.governanceViolations > 0 || inputs.changeRiskEvents > 0) return "review";
  const derivedSummary = isObject(inputs.riskReport?.derivedSummary) ? inputs.riskReport.derivedSummary : undefined;
  const reportedPosture = derivedSummary?.overallPosture;
  if (reportedPosture === "pass" || reportedPosture === "review" || reportedPosture === "blocked") return reportedPosture;
  return "unknown";
}

function sumAiAssets(aiBom: AiBom): number {
  return [
    aiBom.summary.providers,
    aiBom.summary.models,
    aiBom.summary.prompts,
    aiBom.summary.agents,
    aiBom.summary.tools,
    aiBom.summary.vectorStores,
    aiBom.summary.mcpServers,
    aiBom.summary.dataStores
  ].reduce((sum, count) => sum + numberValue(count), 0);
}

function targetPathFromArtifacts(inputs: NormalizedInputs): string | undefined {
  const riskSummary = isObject(inputs.riskReport?.summary) ? inputs.riskReport.summary : undefined;
  return inputs.aiBom?.targetPath ??
    inputs.agentGraph?.targetPath ??
    inputs.aiBomDiff?.currentBom.targetPath ??
    stringValue(riskSummary?.targetPath);
}

function coverageFromRiskReport(riskReport: DashboardData["riskReport"] | undefined): DashboardCoverageSummary | undefined {
  if (!isObject(riskReport?.coverage)) return undefined;
  const coverage = riskReport.coverage;
  return {
    filesDiscovered: numberValue(coverage.filesDiscovered),
    filesScanned: numberValue(coverage.filesScanned),
    filesSkipped: numberValue(coverage.filesSkipped),
    filesExcludedByPolicy: numberValue(coverage.filesExcludedByPolicy),
    filesSkippedBinary: numberValue(coverage.filesSkippedBinary),
    filesSkippedOversized: numberValue(coverage.filesSkippedOversized),
    filesUnreadable: numberValue(coverage.filesUnreadable),
    fileLimitReached: Boolean(coverage.fileLimitReached),
    coveragePercent: numberValue(coverage.coveragePercent),
    coverageStatus: stringValue(coverage.coverageStatus) ?? "unknown"
  };
}

function isAiBom(value: unknown): value is AiBom {
  return isObject(value) &&
    value.tool === "vibeguard" &&
    value.schemaVersion === "vibeguard.aibom.v1" &&
    isAiBomSummary(value.summary) &&
    Array.isArray(value.providers) &&
    Array.isArray(value.models) &&
    Array.isArray(value.prompts) &&
    Array.isArray(value.agents) &&
    Array.isArray(value.tools) &&
    Array.isArray(value.vectorStores) &&
    Array.isArray(value.mcpServers) &&
    Array.isArray(value.dataStores);
}

function governanceFromRiskReport(riskReport: DashboardData["riskReport"] | undefined): AiBomDiffResult | undefined {
  return isObject(riskReport) ? normalizeAiBomDiff(riskReport.aiGovernance) : undefined;
}

function isAiBomSummary(value: unknown): boolean {
  return isObject(value) &&
    isNonNegativeNumber(value.providers) &&
    isNonNegativeNumber(value.models) &&
    isNonNegativeNumber(value.prompts) &&
    isNonNegativeNumber(value.agents) &&
    isNonNegativeNumber(value.tools) &&
    isNonNegativeNumber(value.vectorStores) &&
    isNonNegativeNumber(value.mcpServers) &&
    isNonNegativeNumber(value.dataStores) &&
    Array.isArray(value.highRiskCapabilities) &&
    value.highRiskCapabilities.every(isString);
}

function normalizeAiBomDiff(value: unknown): AiBomDiffResult | undefined {
  if (!isObject(value) || value.tool !== "vibeguard" || value.schemaVersion !== "vibeguard.aibomDiff.v1" || !isObject(value.summary)) {
    return undefined;
  }
  const currentBom = isObject(value.currentBom) ? value.currentBom : {};
  return {
    tool: "vibeguard",
    schemaVersion: "vibeguard.aibomDiff.v1",
    generatedAt: stringValue(value.generatedAt) ?? new Date().toISOString(),
    mode: value.mode === "block" ? "block" : "audit",
    approvedBomPath: stringValue(value.approvedBomPath),
    currentBom: {
      generatedAt: stringValue(currentBom.generatedAt) ?? stringValue(value.generatedAt) ?? "",
      targetPath: stringValue(currentBom.targetPath) ?? ""
    },
    summary: {
      added: numberValue(value.summary.added),
      removed: numberValue(value.summary.removed),
      changed: numberValue(value.summary.changed),
      unauthorized: numberValue(value.summary.unauthorized),
      blockedCapabilities: numberValue(value.summary.blockedCapabilities),
      blocking: numberValue(value.summary.blocking)
    },
    added: Array.isArray(value.added) ? value.added as AiBomDiffResult["added"] : [],
    removed: Array.isArray(value.removed) ? value.removed as AiBomDiffResult["removed"] : [],
    changed: Array.isArray(value.changed) ? value.changed as AiBomDiffResult["changed"] : [],
    violations: Array.isArray(value.violations) ? value.violations.filter(isGovernanceViolation) : []
  };
}

function isAgentGraph(value: unknown): value is AgentCapabilityGraph {
  return isObject(value) &&
    value.tool === "vibeguard" &&
    value.schemaVersion === "vibeguard.agentGraph.v1" &&
    isObject(value.summary) &&
    Array.isArray(value.nodes) &&
    Array.isArray(value.edges) &&
    Array.isArray(value.risks);
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function numberValue(value: unknown, fallback = 0): number {
  return isNonNegativeNumber(value) ? value : fallback;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" ? value : undefined;
}

function isString(value: unknown): value is string {
  return typeof value === "string";
}

function isNonNegativeNumber(value: unknown): value is number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0;
}

function isGovernanceViolation(value: unknown): value is AiBomDiffResult["violations"][number] {
  return isObject(value) &&
    typeof value.id === "string" &&
    typeof value.ruleId === "string" &&
    typeof value.title === "string" &&
    typeof value.severity === "string" &&
    typeof value.assetId === "string" &&
    typeof value.assetKind === "string" &&
    typeof value.assetName === "string" &&
    typeof value.file === "string" &&
    typeof value.line === "number" &&
    typeof value.reason === "string" &&
    typeof value.driftType === "string" &&
    typeof value.evidenceStrength === "string" &&
    typeof value.evidenceSource === "string" &&
    typeof value.blocking === "boolean";
}

function schemaVersionFor(value: unknown): string | undefined {
  return isObject(value) && typeof value.schemaVersion === "string" ? value.schemaVersion : undefined;
}

function displayNameFor(name: string): string {
  const labels: Record<string, string> = {
    aiBom: "AI BOM",
    aiBomDiff: "AI BOM governance diff",
    riskReport: "Risk report",
    agentGraph: "Agent capability graph",
    changeRisk: "AI change-risk",
    grcMappings: "GRC mappings"
  };
  return labels[name] ?? name;
}

function invalidMessageFor(name: string): string {
  return `Invalid ${displayNameFor(name)} artifact; the section will be unavailable in the dashboard.`;
}
