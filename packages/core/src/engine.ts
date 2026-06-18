import { collectGitDiff, enrichDiffFilesWithFullContext, parseUnifiedDiff } from "./diff.ts";
import { buildAiBom, buildAgentCapabilityGraph } from "./aibom/index.ts";
import { applyPolicy, defaultPolicy, loadPolicy, shouldScanFile } from "./policy.ts";
import { applyPolicyCoverage, collectRepository } from "./repository.ts";
import { createVulnerabilityProvider } from "./vulnerabilities.ts";
import { enrichFindingWithEnterpriseContext } from "./frameworks/crosswalk.ts";
import { createFinding } from "./types.ts";
import type { CheckOptions, CheckResult, Confidence, CoverageSummary, DiffFile, Policy, ScanWarning } from "./types.ts";
import { runScanners } from "../../scanners/src/index.ts";
import { runVulnerabilityScanner } from "../../scanners/src/dependencies.ts";

export async function runCheck(options: CheckOptions = {}): Promise<CheckResult> {
  const started = Date.now();
  const cwd = options.cwd ?? process.cwd();
  const policy = options.policy ?? loadPolicy(cwd);
  const collection = collectFilesForCheck(options, cwd, policy);
  const aiBom = buildAiBom(collection.files, { targetPath: collection.targetPath });
  const agentGraph = buildAgentCapabilityGraph(aiBom);
  const scannerFindings = await runScanners(collection.files, policy.enabledScanners);
  const vulnerabilityResult = options.vulnProvider && options.vulnProvider !== "null"
    ? await runVulnerabilityScanner(
      collection.files,
      createVulnerabilityProvider(options.vulnProvider, { timeoutMs: options.vulnProviderTimeoutMs }),
      {
        failMode: options.vulnProviderFailMode ?? "warn",
        concurrency: options.vulnProviderConcurrency
      }
    )
    : { findings: [], warnings: [], source: options.vulnProvider ?? "null", durationMs: 0 };
  const coverageFindings = coveragePolicyFindings(collection.coverage, collection.targetPath, policy);
  const warnings = [...collection.warnings, ...vulnerabilityResult.warnings];
  const enrichedFindings = [...scannerFindings, ...vulnerabilityResult.findings, ...coverageFindings].map(enrichFindingWithEnterpriseContext);
  const filtered = filterFindings(
    applyPolicy(enrichedFindings, policy),
    options.minConfidence ?? policy.minConfidence,
    options.maxFindings,
    options.baselineFindingIds
  );

  return {
    files: collection.files,
    findings: filtered.findings,
    aiBom,
    agentGraph,
    summary: {
      filesChanged: collection.files.length,
      filesScanned: collection.files.length,
      findings: filtered.findings.length,
      blocking: filtered.findings.filter((finding) => finding.blocking).length,
      truncated: filtered.truncated,
      durationMs: Date.now() - started,
      scanMode: collection.scanMode,
      targetPath: collection.targetPath,
      warnings: warnings.length,
      baselineSuppressed: filtered.baselineSuppressed
    },
    coverage: collection.coverage,
    warnings
  };
}

function coveragePolicyFindings(coverage: CoverageSummary, targetPath: string, policy: Policy) {
  const shouldRequireComplete = policy.coverage.requireComplete && coverage.coverageStatus !== "complete";
  const shouldFailUnreadable = policy.coverage.failOnUnreadable && coverage.filesUnreadable > 0;
  if (!shouldRequireComplete && !shouldFailUnreadable) return [];

  return [createFinding({
    ruleId: "coverage-incomplete",
    scanner: "code",
    title: "Scan coverage is incomplete",
    severity: "high",
    confidence: "high",
    riskScore: 80,
    file: targetPath,
    line: 1,
    snippet: `coverage=${coverage.coverageStatus} percent=${coverage.coveragePercent}`,
    evidence: `Coverage status is ${coverage.coverageStatus}; scanned ${coverage.filesScanned} of ${coverage.filesDiscovered} discovered files with ${coverage.filesSkipped} skipped and ${coverage.filesExcludedByPolicy} policy-excluded.`,
    evidenceStrength: "direct",
    evidenceSource: "coverage summary",
    detectionMethod: "coverage-policy",
    why: "A clean scan is not dependable when required coverage is incomplete.",
    suggestedFix: "Review skipped, unreadable, oversized, binary, policy-excluded, or file-limit paths and rerun with complete coverage or documented exclusions.",
    aiFixPrompt: "Review scan coverage configuration and documented exclusions.",
    testSuggestion: "Add a repository scan test that reaches complete coverage or intentionally documents exclusions."
  })];
}

export function runCheckFromDiff(diffText: string, policy: Policy = defaultPolicy()): Promise<CheckResult> {
  return runCheck({ diffText, policy });
}

export type { DiffFile };

function collectFilesForCheck(options: CheckOptions, cwd: string, policy: Policy): {
  files: DiffFile[];
  warnings: ScanWarning[];
  coverage: CoverageSummary;
  scanMode: "repository" | "diff";
  targetPath: string;
} {
  if (options.repositoryFiles) {
    const filtered = options.repositoryFiles.filter((file) => shouldScanFile(file.path, policy));
    return {
      files: filtered,
      warnings: [],
      coverage: coverageForProvidedFiles(options.repositoryFiles.length, filtered.length),
      scanMode: "repository",
      targetPath: options.targetPath ?? cwd
    };
  }

  if (options.diffText || options.staged || options.base) {
    const diffText = options.diffText ?? collectGitDiff({ ...options, cwd });
    const files = enrichDiffFilesWithFullContext(parseUnifiedDiff(diffText), {
      cwd,
      staged: options.staged,
      base: options.base
    });
    const filtered = files.filter((file) => shouldScanFile(file.path, policy));
    return {
      files: filtered,
      warnings: [],
      coverage: coverageForProvidedFiles(files.length, filtered.length),
      scanMode: "diff",
      targetPath: cwd
    };
  }

  const targetPath = options.targetPath ?? cwd;
  const collection = collectRepository(targetPath, {
    maxFiles: options.maxFiles ?? policy.coverage.maxFiles,
    maxFileBytes: options.maxFileBytes ?? policy.coverage.maxFileBytes
  });
  const filtered = collection.files.filter((file) => shouldScanFile(file.path, policy));
  const filesExcludedByPolicy = collection.files.length - filtered.length;
  return {
    files: filtered,
    warnings: collection.warnings,
    coverage: applyPolicyCoverage(collection, filtered.length, filesExcludedByPolicy),
    scanMode: "repository",
    targetPath
  };
}

function coverageForProvidedFiles(filesDiscovered: number, filesScanned: number): CoverageSummary {
  const filesExcludedByPolicy = filesDiscovered - filesScanned;
  const coveragePercent = filesDiscovered === 0 ? 100 : Math.round((filesScanned / filesDiscovered) * 10000) / 100;
  return {
    filesDiscovered,
    filesScanned,
    filesSkipped: 0,
    filesExcludedByPolicy,
    filesSkippedBinary: 0,
    filesSkippedOversized: 0,
    filesUnreadable: 0,
    fileLimitReached: false,
    coveragePercent,
    coverageStatus: filesExcludedByPolicy > 0 ? "partial" : "complete"
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
