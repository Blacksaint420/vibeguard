import { createHash } from "node:crypto";

export type Severity = "low" | "medium" | "high" | "critical";
export type Confidence = "low" | "medium" | "high";
export type OutputFormat = "table" | "json" | "sarif" | "markdown";
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
  aiPrompts: {
    enabled: boolean;
  };
};

export type CheckOptions = {
  cwd?: string;
  staged?: boolean;
  base?: string;
  format?: OutputFormat;
  diffText?: string;
  policy?: Policy;
};

export type CheckResult = {
  findings: Finding[];
  files: DiffFile[];
  summary: {
    filesChanged: number;
    findings: number;
    blocking: number;
  };
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
  query(packageName: string, version?: string): Promise<Vulnerability[]>;
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

