import { createHash } from "node:crypto";

export type Severity = "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type OutputFormat = "table" | "json" | "sarif" | "markdown" | "html";
export type ScannerName = "code" | "secrets" | "dependencies" | "docker" | "actions" | "sensitive-files";

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
  why: string;
  suggestedFix: string;
  aiFixPrompt: string;
  testSuggestion: string;
  blocking: boolean;
};

export type FindingInput = Omit<Finding, "id" | "blocking"> & {
  id?: string;
  blocking?: boolean;
};

export type Suppression = {
  rule?: string;
  file?: string;
  line?: number;
  reason?: string;
};

export type Policy = {
  mode: "warn" | "block";
  enabledScanners: ScannerName[];
  blockSeverities: Severity[];
  include: string[];
  exclude: string[];
  suppressions: Suppression[];
  minConfidence?: Confidence;
  aiPrompts: {
    enabled: boolean;
  };
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
  policy?: Policy;
};

export type ReportRecommendation = {
  title: string;
  priority: Severity;
  ruleId: string;
  file: string;
  line: number;
  suggestedFix: string;
  aiFixPrompt: string;
  blocking: boolean;
};

export type CheckResult = {
  findings: Finding[];
  files: DiffFile[];
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

export type ScanWarning = {
  path: string;
  message: string;
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
    blocking: input.blocking ?? false
  };
}

export function severityRank(severity: Severity): number {
  if (severity === "critical") return 4;
  if (severity === "high") return 3;
  if (severity === "medium") return 2;
  return 1;
}
