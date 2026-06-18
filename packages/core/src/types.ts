import { createHash } from "node:crypto";
import type { AgentCapabilityGraph, AiBom } from "./aibom/index.ts";

export type Severity = "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type EvidenceStrength = "direct" | "same-file" | "same-module" | "repository-inferred" | "unknown";
export type OutputFormat =
  | "table"
  | "json"
  | "sarif"
  | "markdown"
  | "html"
  | "risk-json"
  | "aibom-json"
  | "aibom-markdown"
  | "graph-json"
  | "graph-markdown";
export type ScannerName = "code" | "secrets" | "dependencies" | "docker" | "actions" | "sensitive-files" | "ai";
export type FrameworkId = "owasp-llm-2025" | "nist-ai-rmf" | "mitre-atlas" | "google-saif";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type RuleStability = "stable" | "experimental" | "custom";
export type OwaspLlmCategoryId =
  | "LLM01:2025"
  | "LLM02:2025"
  | "LLM03:2025"
  | "LLM04:2025"
  | "LLM05:2025"
  | "LLM06:2025"
  | "LLM07:2025"
  | "LLM08:2025"
  | "LLM09:2025"
  | "LLM10:2025";

export type OwaspLlmCategory = {
  id: OwaspLlmCategoryId;
  name: string;
};

export type RuleMetadata = {
  id: string;
  name: string;
  version: string;
  stability: RuleStability;
  scanner?: ScannerName;
};

export type FrameworkMapping = {
  framework: FrameworkId;
  id: string;
  name: string;
  sourceVersion: string;
};

export type GrcRisk = {
  category: string;
  likelihood: RiskLevel;
  impact: RiskLevel;
  severity: RiskLevel;
  controlOwner: "engineering" | "security" | "grc" | "platform";
};

export type ReportPosture = "pass" | "review" | "blocked";
export type MergeRecommendation = "Safe to proceed" | "Review before merge" | "Do not merge";
export type ReportOwnerSuggestion = "Engineering" | "Security" | "Platform" | "GRC";
export type SeverityDistribution = Record<Severity, number>;

export type ReportTopRisk = {
  title: string;
  ruleId: string;
  severity: Severity;
  riskScore: number;
  file: string;
  line: number;
  blocking: boolean;
  owner: ReportOwnerSuggestion;
  impact?: string;
  suggestedFix: string;
  owasp?: OwaspLlmCategory;
};

export type ReportControlGapSummary = {
  gap: string;
  count: number;
  owner: ReportOwnerSuggestion;
};

export type DerivedReportSummary = {
  overallPosture: ReportPosture;
  businessRiskLevel: RiskLevel;
  mergeRecommendation: MergeRecommendation;
  severityDistribution: SeverityDistribution;
  topRisks: ReportTopRisk[];
  controlGapSummary: ReportControlGapSummary[];
  ownerSuggestion: ReportOwnerSuggestion;
};

export type ChangedLine = {
  line: number;
  content: string;
};

export type DiffFile = {
  path: string;
  oldPath: string;
  status: "added" | "modified" | "deleted" | "renamed";
  addedLines: ChangedLine[];
  removedLines: ChangedLine[];
  allLines?: ChangedLine[];
};

export type Finding = {
  id: string;
  ruleId: string;
  scanner?: ScannerName;
  title: string;
  severity: Severity;
  confidence: Confidence;
  riskScore: number;
  file: string;
  line: number;
  snippet: string;
  owasp?: OwaspLlmCategory;
  rule?: RuleMetadata;
  frameworks?: FrameworkMapping[];
  risk?: GrcRisk;
  controlGaps?: string[];
  evidence?: string;
  evidenceStrength: EvidenceStrength;
  evidenceSource: string;
  detectionMethod: string;
  relatedLocations?: Array<{ file: string; line: number; label?: string }>;
  attackPath?: string;
  impact?: string;
  why: string;
  suggestedFix: string;
  aiFixPrompt: string;
  testSuggestion: string;
  blocking: boolean;
};

export type FindingInput = Omit<Finding, "id" | "blocking" | "evidenceStrength" | "evidenceSource" | "detectionMethod" | "relatedLocations"> & {
  id?: string;
  blocking?: boolean;
  evidenceStrength?: EvidenceStrength;
  evidenceSource?: string;
  detectionMethod?: string;
  relatedLocations?: Array<{ file: string; line: number; label?: string }>;
};

export type Suppression = {
  rule?: string;
  file?: string;
  line?: number;
  reason?: string;
  reviewer?: string;
  expires?: string;
};

export type SuppressionPolicy = {
  requireReason: boolean;
  requireReviewer: boolean;
  requireExpiration: boolean;
};

export type AiGovernanceMode = "audit" | "block";

export type AiGovernanceAssetSelector = {
  kind?: string;
  id?: string;
  name?: string;
  file?: string;
  capabilities?: string[];
};

export type AiGovernanceException = {
  assetId: string;
  reason: string;
  reviewer: string;
  expires: string;
};

export type AiGovernancePolicy = {
  mode: AiGovernanceMode;
  approvedBom?: string;
  blockOnDrift: boolean;
  allowedProviders: string[];
  blockedProviders: string[];
  allowedModels: string[];
  blockedModels: string[];
  allowedMcpServers: string[];
  blockedCapabilities: string[];
  allowedCapabilities: string[];
  assetAllowlist: AiGovernanceAssetSelector[];
  exceptions: AiGovernanceException[];
  changeRisk: {
    mode: AiGovernanceMode;
    blockSeverities: Severity[];
    blockEvents: string[];
  };
};

export type AiGovernanceViolation = {
  id: string;
  ruleId: string;
  title: string;
  severity: Severity;
  assetId: string;
  assetKind: string;
  assetName: string;
  file: string;
  line: number;
  reason: string;
  driftType: "added" | "removed" | "changed" | "unauthorized" | "blocked-capability";
  capability?: string;
  evidenceStrength: EvidenceStrength;
  evidenceSource: string;
  blocking: boolean;
};

export type AiBomAssetDelta = {
  assetId: string;
  kind: string;
  name: string;
  file: string;
  line: number;
  capabilities: string[];
  fingerprint: string;
  previousFingerprint?: string;
  changes: string[];
};

export type AiBomDiffResult = {
  tool: "vibeguard";
  schemaVersion: "vibeguard.aibomDiff.v1";
  generatedAt: string;
  mode: AiGovernanceMode;
  approvedBomPath?: string;
  currentBom: {
    generatedAt: string;
    targetPath: string;
  };
  summary: {
    added: number;
    removed: number;
    changed: number;
    unauthorized: number;
    blockedCapabilities: number;
    blocking: number;
  };
  added: AiBomAssetDelta[];
  removed: AiBomAssetDelta[];
  changed: AiBomAssetDelta[];
  violations: AiGovernanceViolation[];
};

export type Policy = {
  mode: "warn" | "block";
  enabledScanners: ScannerName[];
  blockSeverities: Severity[];
  include: string[];
  exclude: string[];
  suppressions: Suppression[];
  suppressionPolicy: SuppressionPolicy;
  minConfidence?: Confidence;
  coverage: {
    requireComplete: boolean;
    maxFiles?: number;
    maxFileBytes?: number;
    failOnUnreadable: boolean;
  };
  aiPrompts: {
    enabled: boolean;
  };
  aiGovernance: AiGovernancePolicy;
};

export type CheckOptions = {
  cwd?: string;
  targetPath?: string;
  staged?: boolean;
  base?: string;
  format?: OutputFormat;
  diffText?: string;
  repositoryFiles?: DiffFile[];
  minConfidence?: Confidence;
  maxFindings?: number;
  baselineFindingIds?: string[];
  vulnProvider?: "null" | "mock" | "osv";
  vulnProviderFailMode?: "warn" | "fail";
  vulnProviderTimeoutMs?: number;
  vulnProviderConcurrency?: number;
  strictCoverage?: boolean;
  maxFiles?: number;
  maxFileBytes?: number;
  policy?: Policy;
  approvedAiBom?: AiBom;
  aiGovernanceMode?: AiGovernanceMode;
};

export type ReportRecommendation = {
  title: string;
  priority: Severity;
  ruleId: string;
  file: string;
  line: number;
  owasp?: OwaspLlmCategory;
  attackPath?: string;
  impact?: string;
  suggestedFix: string;
  aiFixPrompt: string;
  blocking: boolean;
};

export type CheckResult = {
  findings: Finding[];
  files: DiffFile[];
  aiBom?: AiBom;
  agentGraph?: AgentCapabilityGraph;
  aiGovernance?: AiBomDiffResult;
  summary: {
    filesChanged: number;
    filesScanned: number;
    findings: number;
    blocking: number;
    truncated: boolean;
    durationMs: number;
    scanMode: "repository" | "diff";
    targetPath: string;
    warnings: number;
    baselineSuppressed: number;
  };
  coverage: CoverageSummary;
  warnings: ScanWarning[];
};

export type BaselineFinding = {
  id: string;
  ruleId: string;
  file: string;
  line: number;
};

export type Baseline = {
  tool: "vibeguard";
  version: string;
  generatedAt: string;
  targetPath: string;
  findings: BaselineFinding[];
};

export type ScanWarningCode = "unreadable" | "binary" | "oversized" | "outside-root" | "file-limit" | "policy-excluded" | "vulnerability-provider";

export type ScanWarning = {
  code?: ScanWarningCode;
  path: string;
  message: string;
};

export type CoverageSummary = {
  filesDiscovered: number;
  filesScanned: number;
  filesSkipped: number;
  filesExcludedByPolicy: number;
  filesSkippedBinary: number;
  filesSkippedOversized: number;
  filesUnreadable: number;
  fileLimitReached: boolean;
  coveragePercent: number;
  coverageStatus: "complete" | "partial" | "failed";
};

export type Vulnerability = {
  id: string;
  packageName: string;
  installedVersion?: string;
  severity: Severity;
  summary: string;
};

export type VulnerabilityProvider = {
  name: string;
  query(packageName: string, version?: string, ecosystem?: string): Promise<Vulnerability[]>;
};

export type VulnerabilityProviderResult = {
  vulnerabilities: Vulnerability[];
  warnings: ScanWarning[];
  source: string;
  freshness: "live" | "cache" | "unavailable";
  durationMs: number;
};

export function createFindingId(ruleId: string, file: string, line: number, snippet: string): string {
  const hash = createHash("sha256")
    .update(`${ruleId}\0${file}\0${line}\0${snippet}`)
    .digest("hex")
    .slice(0, 12);
  return `${ruleId}:${hash}`;
}

export function createFinding(input: FindingInput): Finding {
  return {
    ...input,
    id: input.id ?? createFindingId(input.ruleId, input.file, input.line, input.snippet),
    rule: input.rule,
    frameworks: input.frameworks ?? [],
    risk: input.risk,
    controlGaps: input.controlGaps ?? [],
    evidenceStrength: input.evidenceStrength ?? "direct",
    evidenceSource: input.evidenceSource ?? [input.file, input.line].join(":"),
    detectionMethod: input.detectionMethod ?? "scanner-rule-match",
    relatedLocations: input.relatedLocations ?? [],
    blocking: input.blocking ?? false
  };
}

export function severityRank(severity: Severity): number {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  return 1;
}
