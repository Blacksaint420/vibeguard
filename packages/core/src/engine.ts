import { collectGitDiff, parseUnifiedDiff } from "./diff.ts";
import { applyPolicy, defaultPolicy, loadPolicy, shouldScanFile } from "./policy.ts";
import { collectRepository } from "./repository.ts";
import { createVulnerabilityProvider } from "./vulnerabilities.ts";
import type { CheckOptions, CheckResult, Confidence, DiffFile, Policy, ScanWarning } from "./types.ts";
import { runScanners } from "../../scanners/src/index.ts";
import { runVulnerabilityScanner } from "../../scanners/src/dependencies.ts";

export async function runCheck(options: CheckOptions = {}): Promise<CheckResult> {
  const started = Date.now();
  const cwd = options.cwd ?? process.cwd();
  const policy = options.policy ?? loadPolicy(cwd);
  const collection = collectFilesForCheck(options, cwd, policy);
  const scannerFindings = await runScanners(collection.files, policy.enabledScanners);
  const vulnerabilityFindings = options.vulnProvider && options.vulnProvider !== "null"
    ? await runVulnerabilityScanner(collection.files, createVulnerabilityProvider(options.vulnProvider))
    : [];
  const filtered = filterFindings(
    applyPolicy([...scannerFindings, ...vulnerabilityFindings], policy),
    options.minConfidence ?? policy.minConfidence,
    options.maxFindings,
    options.baselineFindingIds
  );

  return {
    files: collection.files,
    findings: filtered.findings,
    summary: {
      filesChanged: collection.files.length,
      filesScanned: collection.files.length,
      findings: filtered.findings.length,
      blocking: filtered.findings.filter((finding) => finding.blocking).length,
      truncated: filtered.truncated,
      durationMs: Date.now() - started,
      scanMode: collection.scanMode,
      targetPath: collection.targetPath,
      warnings: collection.warnings.length,
      baselineSuppressed: filtered.baselineSuppressed
    },
    warnings: collection.warnings
  };
}

export function runCheckFromDiff(diffText: string, policy: Policy = defaultPolicy()): Promise<CheckResult> {
  return runCheck({ diffText, policy });
}

export type { DiffFile };

function collectFilesForCheck(options: CheckOptions, cwd: string, policy: Policy): {
  files: DiffFile[];
  warnings: ScanWarning[];
  scanMode: "repository" | "diff";
  targetPath: string;
} {
  if (options.repositoryFiles) {
    return {
      files: options.repositoryFiles.filter((file) => shouldScanFile(file.path, policy)),
      warnings: [],
      scanMode: "repository",
      targetPath: options.targetPath ?? cwd
    };
  }

  if (options.diffText || options.staged || options.base) {
    const diffText = options.diffText ?? collectGitDiff({ ...options, cwd });
    return {
      files: parseUnifiedDiff(diffText).filter((file) => shouldScanFile(file.path, policy)),
      warnings: [],
      scanMode: "diff",
      targetPath: cwd
    };
  }

  const targetPath = options.targetPath ?? cwd;
  const collection = collectRepository(targetPath);
  return {
    files: collection.files.filter((file) => shouldScanFile(file.path, policy)),
    warnings: collection.warnings,
    scanMode: "repository",
    targetPath
  };
}

function filterFindings(
  findings: Awaited<ReturnType<typeof applyPolicy>>,
  minConfidence?: Confidence,
  maxFindings?: number,
  baselineFindingIds: string[] = []
) {
  const confidenceRank = { low: 1, medium: 2, high: 3 };
  const minimum = minConfidence ? confidenceRank[minConfidence] : 0;
  const confidenceFiltered = findings.filter((finding) => confidenceRank[finding.confidence] >= minimum);
  const baselineIds = new Set(baselineFindingIds);
  const baselineFiltered = confidenceFiltered.filter((finding) => !baselineIds.has(finding.id));
  const limited = typeof maxFindings === "number" ? baselineFiltered.slice(0, maxFindings) : baselineFiltered;
  return {
    findings: limited,
    truncated: limited.length < baselineFiltered.length,
    baselineSuppressed: confidenceFiltered.length - baselineFiltered.length
  };
}
