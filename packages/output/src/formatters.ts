import { severityRank } from "../../core/src/types.ts";
import { summarizeOwaspFindings } from "../../core/src/owasp.ts";
import { summarizeGrcRisks, UNMAPPED_GRC_RISK_CATEGORY } from "../../core/src/risk.ts";
import type { AgentCapabilityGraph, AiAsset, AiBom } from "../../core/src/aibom/index.ts";
import type {
  AiBomDiffResult,
  CheckResult,
  DerivedReportSummary,
  Finding,
  ReportControlGapSummary,
  ReportOwnerSuggestion,
  ReportRecommendation,
  ReportTopRisk,
  RiskLevel,
  Severity,
  SeverityDistribution
} from "../../core/src/types.ts";

type ScanReportLike = Finding[] | CheckResult;
type AiBomReportLike = { kind: "aibom"; bom: AiBom };
type AiBomDiffReportLike = { kind: "aibom-diff"; diff: AiBomDiffResult };
type AgentGraphReportLike = { kind: "graph"; graph: AgentCapabilityGraph };
type ReportLike = ScanReportLike | AiBomReportLike | AiBomDiffReportLike | AgentGraphReportLike;

type GrcRiskEntry = {
  category: string;
  highestSeverity: Finding["severity"];
  frameworks: NonNullable<Finding["frameworks"]>;
  controlGaps: string[];
  technicalEvidence: Array<{
    id: string;
    ruleId: string;
    ruleVersion?: string;
    title: string;
    severity: Finding["severity"];
    confidence: Finding["confidence"];
    file: string;
    line: number;
    snippet: string;
    evidence: string;
    scanner: string;
    impact: string;
    suggestedFix: string;
    blocking: boolean;
  }>;
};

export function buildDerivedReportSummary(reportLike: ScanReportLike): DerivedReportSummary {
  const report = normalizeReport(reportLike);
  const findings = report.findings;
  const severityDistribution = buildSeverityDistribution(findings);
  const topRisks = buildTopRisks(findings);
  const controlGapSummary = buildControlGapSummary(findings);
  const businessRiskLevel = highestBusinessRisk(findings);
  const overallPosture = findings.length === 0
    ? "pass"
    : report.summary.blocking > 0 || findings.some((finding) => finding.blocking)
      ? "blocked"
      : "review";
  const mergeRecommendation = overallPosture === "pass"
    ? "Safe to proceed"
    : overallPosture === "blocked"
      ? "Do not merge"
      : "Review before merge";

  return {
    overallPosture,
    businessRiskLevel,
    mergeRecommendation,
    severityDistribution,
    topRisks,
    controlGapSummary,
    ownerSuggestion: suggestOwner(findings)
  };
}

function buildSeverityDistribution(findings: Finding[]): SeverityDistribution {
  return findings.reduce<SeverityDistribution>(
    (distribution, finding) => ({
      ...distribution,
      [finding.severity]: distribution[finding.severity] + 1
    }),
    { critical: 0, high: 0, medium: 0, low: 0 }
  );
}

function buildTopRisks(findings: Finding[], limit = 5): ReportTopRisk[] {
  return sortFindingsForDecision(findings)
    .slice(0, limit)
    .map((finding) => ({
      title: finding.title,
      ruleId: finding.ruleId,
      severity: finding.severity,
      riskScore: finding.riskScore,
      file: finding.file,
      line: finding.line,
      blocking: finding.blocking,
      owner: ownerLabel(finding.risk?.controlOwner),
      impact: finding.impact,
      suggestedFix: finding.suggestedFix,
      owasp: finding.owasp
    }));
}

function buildControlGapSummary(findings: Finding[]): ReportControlGapSummary[] {
  const byGap = new Map<string, { count: number; ownerScores: Map<ReportOwnerSuggestion, number> }>();
  for (const finding of findings) {
    const owner = ownerLabel(finding.risk?.controlOwner);
    for (const gap of finding.controlGaps ?? []) {
      const existing = byGap.get(gap) ?? { count: 0, ownerScores: new Map<ReportOwnerSuggestion, number>() };
      existing.count += 1;
      existing.ownerScores.set(owner, (existing.ownerScores.get(owner) ?? 0) + 1);
      byGap.set(gap, existing);
    }
  }

  return [...byGap.entries()]
    .map(([gap, entry]) => ({
      gap,
      count: entry.count,
      owner: highestOwner(entry.ownerScores)
    }))
    .sort((left, right) => right.count - left.count || left.gap.localeCompare(right.gap))
    .slice(0, 8);
}

function highestBusinessRisk(findings: Finding[]): RiskLevel {
  return findings.reduce<RiskLevel>((highest, finding) => {
    const level = finding.risk?.severity ?? finding.severity;
    return severityRank(level) > severityRank(highest) ? level : highest;
  }, "low");
}

function suggestOwner(findings: Finding[]): ReportOwnerSuggestion {
  const scores = new Map<ReportOwnerSuggestion, number>();
  for (const finding of findings) {
    const owner = ownerLabel(finding.risk?.controlOwner);
    const weight = (finding.blocking ? 3 : 1) + severityRank(finding.risk?.severity ?? finding.severity);
    scores.set(owner, (scores.get(owner) ?? 0) + weight);
  }
  return highestOwner(scores);
}

function highestOwner(scores: Map<ReportOwnerSuggestion, number>): ReportOwnerSuggestion {
  const orderedOwners: ReportOwnerSuggestion[] = ["Engineering", "Security", "Platform", "GRC"];
  return orderedOwners
    .map((owner) => ({ owner, score: scores.get(owner) ?? 0 }))
    .sort((left, right) => right.score - left.score || orderedOwners.indexOf(left.owner) - orderedOwners.indexOf(right.owner))[0].owner;
}

function ownerLabel(owner: NonNullable<Finding["risk"]>["controlOwner"] | undefined): ReportOwnerSuggestion {
  if (owner === "security") return "Security";
  if (owner === "platform") return "Platform";
  if (owner === "grc") return "GRC";
  return "Engineering";
}

function sortFindingsForDecision(findings: Finding[]): Finding[] {
  return [...findings].sort((left, right) =>
    Number(right.blocking) - Number(left.blocking)
    || severityRank(right.risk?.severity ?? right.severity) - severityRank(left.risk?.severity ?? left.severity)
    || severityRank(right.severity) - severityRank(left.severity)
    || right.riskScore - left.riskScore
    || left.file.localeCompare(right.file)
    || left.line - right.line
  );
}

export function renderJson(reportLike: ScanReportLike): string {
  const report = normalizeReport(reportLike);
  const derivedSummary = buildDerivedReportSummary(report);
  return JSON.stringify(
    {
      tool: "vibeguard",
      version: "0.1.0",
      summary: report.summary,
      coverage: report.coverage,
      derivedSummary,
      owaspSummary: summarizeOwaspFindings(report.findings),
      warnings: report.warnings,
      recommendations: buildRecommendations(report),
      aiGovernance: report.aiGovernance,
      findings: report.findings
    },
    null,
    2
  );
}

export function renderRiskJson(reportLike: ScanReportLike): string {
  const report = normalizeReport(reportLike);
  const derivedSummary = buildDerivedReportSummary(report);
  return JSON.stringify(
    {
      tool: "vibeguard",
      version: "0.1.0",
      reportType: "grc-risk",
      summary: report.summary,
      coverage: report.coverage,
      derivedSummary,
      warnings: report.warnings,
      riskSummary: summarizeGrcRisks(report.findings),
      risks: buildGrcRisks(report.findings),
      aiBom: report.aiBom,
      agentGraph: report.agentGraph,
      aiGovernance: report.aiGovernance
    },
    null,
    2
  );
}

export function renderTable(reportLike: ScanReportLike): string {
  const report = normalizeReport(reportLike);
  const derivedSummary = buildDerivedReportSummary(report);
  const findings = sortFindingsForDecision(report.findings);
  const lines = [
    ...renderModuleHeader("Security Scan", "Decision-grade summary for merge review, security triage, and audit handoff."),
    sectionTitle("Decision"),
    ...renderDecisionSnapshot(report, derivedSummary),
    "",
    sectionTitle("Scan Scope"),
    ...renderScanScope(report),
    "",
    sectionTitle("Severity Mix"),
    ...renderSeverityDistribution(derivedSummary.severityDistribution)
  ];

  if (findings.length === 0) {
    lines.push(
      "",
      sectionTitle("Result Details"),
      "No findings were generated at the active policy and confidence threshold.",
      "",
      sectionTitle("Recommended Follow-Up"),
      "- Run with --min-confidence medium for broader audit coverage.",
      "- Scan the application source directory directly, for example: vibeguard check ./src --format table.",
      "- Use vibeguard aibom ./src and vibeguard graph ./src for AI assets and agent capability paths.",
      "",
      sectionTitle("Audit Footer"),
      renderScanFooter(report),
      ""
    );
    return lines.join("\n");
  }

  lines.push(
    "",
    sectionTitle("Priority Action Plan"),
    ...renderPriorityActionPlan(derivedSummary),
    "",
    sectionTitle("Control Gaps"),
    ...renderControlGapSummary(derivedSummary),
    "",
    sectionTitle("Top Risks"),
    ...renderTopRiskTable(derivedSummary),
    "",
    sectionTitle("Finding Evidence"),
    ...findings.map((finding, index) => renderFindingCard(finding, index + 1)),
    sectionTitle("Audit Footer"),
    renderRecommendationFooter(report),
    renderScanFooter(report),
    ""
  );

  return lines.join("\n");
}

export function renderRiskConsole(reportLike: ScanReportLike): string {
  const report = normalizeReport(reportLike);
  const derivedSummary = buildDerivedReportSummary(report);
  const grcRisks = buildGrcRisks(report.findings);
  const riskSummary = summarizeGrcRisks(report.findings);

  return [
    ...renderModuleHeader("GRC Risk Brief", "Control-oriented view for security, platform, and governance review."),
    sectionTitle("Decision"),
    ...renderDecisionSnapshot(report, derivedSummary),
    "",
    sectionTitle("Risk Categories"),
    ...renderRiskCategoryTable(grcRisks),
    "",
    sectionTitle("Framework Coverage"),
    ...renderFrameworkCoverage(riskSummary.byFramework),
    "",
    sectionTitle("Control Gaps"),
    ...renderControlGapSummary(derivedSummary),
    "",
    sectionTitle("Evidence Queue"),
    ...renderTopRiskTable(derivedSummary),
    "",
    sectionTitle("Audit Footer"),
    renderScanFooter(report),
    ""
  ].join("\n");
}

export function renderMarkdown(reportLike: ScanReportLike): string {
  const report = normalizeReport(reportLike);
  const findings = report.findings;
  const derivedSummary = buildDerivedReportSummary(report);
  const bySeverity = groupBy(findings, "severity");
  const byScanner = groupBy(findings, "scanner");
  const owaspSummary = summarizeOwaspFindings(findings);
  const grcRisks = buildGrcRisks(findings);
  const lines = [
    "## VibeGuard Security Summary",
    "",
    `- Findings: ${report.summary.findings}`,
    `- Blocking: ${report.summary.blocking}`,
    `- Files scanned: ${report.summary.filesScanned}`,
    `- Coverage status: ${report.coverage.coverageStatus}`,
    `- Coverage percent: ${report.coverage.coveragePercent}`,
    `- Scan mode: ${report.summary.scanMode}`,
    `- Warnings: ${report.summary.warnings}`,
    `- Baseline suppressed: ${report.summary.baselineSuppressed}`,
    `- Posture: ${derivedSummary.overallPosture}`,
    `- Business risk: ${derivedSummary.businessRiskLevel}`,
    `- Merge recommendation: ${derivedSummary.mergeRecommendation}`,
    `- Owner suggestion: ${derivedSummary.ownerSuggestion}`,
    "",
    "### Decision Summary",
    "",
    `- ${derivedSummary.mergeRecommendation}`,
    `- Top risk: ${derivedSummary.topRisks[0]?.title ?? "none"}`,
    "",
    "### Findings By Severity",
    "",
    ...Object.entries(bySeverity).map(([severity, count]) => `- ${severity}: ${count}`),
    "",
    "### Findings By Scanner",
    "",
    ...Object.entries(byScanner).map(([scanner, count]) => `- ${scanner}: ${count}`),
    "",
    "### OWASP LLM Mapping",
    "",
    ...(owaspSummary.length === 0
      ? ["- No OWASP LLM mapped findings."]
      : owaspSummary.map((entry) => `- ${entry.id} ${entry.name}: ${entry.count} finding${entry.count === 1 ? "" : "s"} (${entry.blocking} blocking)`)),
    "",
    "### GRC Risk Mapping",
    "",
    ...(grcRisks.length === 0
      ? ["- No GRC risk mapped findings."]
      : grcRisks.map((risk) => {
        const frameworks = risk.frameworks.map((framework) => `${framework.framework}:${framework.id}`).join(", ") || "none";
        const controlGaps = risk.controlGaps.join(", ") || "none";
        return `- ${escapeMarkdown(risk.category)}: ${risk.technicalEvidence.length} finding${risk.technicalEvidence.length === 1 ? "" : "s"}; highest severity ${risk.highestSeverity}; frameworks ${escapeMarkdown(frameworks)}; control gaps ${escapeMarkdown(controlGaps)}`;
      })),
    "",
    "### AI BOM Governance",
    "",
    ...(report.aiGovernance
      ? [
        `- Added: ${report.aiGovernance.summary.added}`,
        `- Removed: ${report.aiGovernance.summary.removed}`,
        `- Changed: ${report.aiGovernance.summary.changed}`,
        `- Unauthorized: ${report.aiGovernance.summary.unauthorized}`,
        `- Blocked capabilities: ${report.aiGovernance.summary.blockedCapabilities}`,
        `- Blocking: ${report.aiGovernance.summary.blocking}`,
        "",
        ...(report.aiGovernance.violations.length === 0
          ? ["- No AI BOM governance violations detected."]
          : report.aiGovernance.violations.map((violation) => `- ${violation.blocking ? "BLOCK" : "AUDIT"} ${violation.severity}: ${escapeMarkdown(violation.assetKind)} ${escapeMarkdown(violation.assetName)} at ${escapeMarkdown(violation.file)}:${violation.line} - ${escapeMarkdown(violation.reason)}`))
      ]
      : ["- AI BOM governance was not evaluated."]),
    ""
  ];

  lines.push("### Recommended Next Actions", "");
  const recommendations = buildRecommendations(report);
  if (recommendations.length === 0) {
    lines.push("- No action needed.", "");
  } else {
    for (const recommendation of recommendations) {
      lines.push(
        `- ${recommendation.blocking ? "Blocker" : "Review"}: ${escapeMarkdown(recommendation.title)} in ${escapeMarkdown(recommendation.file)}:${recommendation.line}. ${escapeMarkdown(recommendation.suggestedFix)}`
      );
    }
    lines.push("");
  }

  if (findings.length === 0) {
    lines.push("No findings.", "");
    return lines.join("\n");
  }

  for (const finding of findings) {
    lines.push(`### ${escapeMarkdown(finding.title)}`);
    lines.push("");
    lines.push(`- Status: ${finding.blocking ? "BLOCK" : "WARN"}`);
    lines.push(`- OWASP: ${finding.owasp ? escapeMarkdown(`${finding.owasp.id} ${finding.owasp.name}`) : "Code Security"}`);
    lines.push(`- Location: ${escapeMarkdown(finding.file)}:${finding.line}`);
    lines.push(`- Evidence: ${escapeMarkdown(finding.evidence ?? finding.snippet)}`);
    lines.push(`- Attack path: ${escapeMarkdown(finding.attackPath ?? finding.why)}`);
    lines.push(`- Impact: ${escapeMarkdown(finding.impact ?? finding.why)}`);
    lines.push(`- Fix: ${escapeMarkdown(finding.suggestedFix)}`);
    lines.push("");
  }
  lines.push("");
  return lines.join("\n");
}

export function renderSarif(reportLike: ScanReportLike): string {
  const report = normalizeReport(reportLike);
  const findings = report.findings;
  const governanceViolations = report.aiGovernance?.violations ?? [];
  const rules = [...new Map([
    ...findings.map((finding) => [
      finding.ruleId,
      {
        id: finding.ruleId,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.why },
        help: { text: finding.suggestedFix }
      }
    ] as const),
    ...governanceViolations.map((violation) => [
      violation.ruleId,
      {
        id: violation.ruleId,
        shortDescription: { text: violation.title },
        fullDescription: { text: violation.reason },
        help: { text: "Review AI BOM governance policy, approved BOM, and exception workflow." }
      }
    ] as const)
  ]).values()];

  return JSON.stringify(
    {
      version: "2.1.0",
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      runs: [
        {
          tool: {
            driver: {
              name: "VibeGuard",
              informationUri: "https://github.com/local/vibeguard",
              rules
            }
          },
          invocations: [
            {
              executionSuccessful: true,
              toolExecutionNotifications: report.warnings.map((warning) => ({
                level: "warning",
                message: { text: `${warning.path}: ${warning.message}` }
              })),
              properties: {
                scanMode: report.summary.scanMode,
                filesScanned: report.summary.filesScanned,
                durationMs: report.summary.durationMs,
                truncated: report.summary.truncated,
                baselineSuppressed: report.summary.baselineSuppressed,
                owaspSummary: summarizeOwaspFindings(findings),
                recommendations: buildRecommendations(report)
              }
            }
          ],
          results: [
            ...findings.map((finding) => ({
            ruleId: finding.ruleId,
            level: sarifLevel(finding.severity),
            message: { text: `${finding.title}: ${finding.why}` },
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: finding.file },
                  region: {
                    startLine: finding.line,
                    snippet: { text: finding.snippet }
                  }
                }
              }
            ],
            properties: {
              confidence: finding.confidence,
              riskScore: finding.riskScore,
              blocking: finding.blocking,
              owasp: finding.owasp,
              evidence: finding.evidence,
              attackPath: finding.attackPath,
              impact: finding.impact,
              aiFixPrompt: finding.aiFixPrompt,
              testSuggestion: finding.testSuggestion
            }
          })),
            ...governanceViolations.map((violation) => ({
              ruleId: violation.ruleId,
              level: sarifLevel(violation.severity),
              message: { text: `${violation.title}: ${violation.reason}` },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: violation.file },
                    region: {
                      startLine: violation.line
                    }
                  }
                }
              ],
              properties: {
                blocking: violation.blocking,
                assetId: violation.assetId,
                assetKind: violation.assetKind,
                assetName: violation.assetName,
                driftType: violation.driftType,
                capability: violation.capability,
                evidenceStrength: violation.evidenceStrength,
                evidenceSource: violation.evidenceSource
              }
            }))
          ]
        }
      ]
    },
    null,
    2
  );
}

export function renderHtml(reportLike: ScanReportLike): string {
  const report = normalizeReport(reportLike);
  const derivedSummary = buildDerivedReportSummary(report);
  const recommendations = buildRecommendations(report);
  const owaspSummary = summarizeOwaspFindings(report.findings);
  const grcRisks = buildGrcRisks(report.findings);
  const generatedAt = new Date().toISOString();
  return [
    "<!doctype html>",
    "<html lang=\"en\">",
    "<head>",
    "<meta charset=\"utf-8\">",
    "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">",
    "<title>VibeGuard Report</title>",
    "<style>:root{color-scheme:light;--ink:#172033;--muted:#5f6b7a;--line:#d8dee8;--panel:#fff;--bg:#f5f7fb;--critical:#b42318;--high:#c25100;--medium:#946200;--low:#287a3e;--brand:#1d4ed8;}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,\"Segoe UI\",sans-serif;line-height:1.45;}main{max-width:1200px;margin:0 auto;padding:24px;}header.hero{background:#101827;color:#fff;border-radius:8px;padding:24px;margin-bottom:18px;}h1,h2,h3{margin:0 0 10px;}p{margin:0 0 10px}.meta{display:flex;flex-wrap:wrap;gap:8px;margin-top:12px}.pill,.badge{display:inline-flex;align-items:center;border-radius:999px;padding:4px 9px;font-size:12px;font-weight:700;background:#e9eef7;color:#27364f}.hero .pill{background:#293447;color:#f5f7fb}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:12px}.panel,.card,details{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:16px;margin:12px 0;box-shadow:0 1px 2px rgba(15,23,42,.04)}.card strong{display:block;font-size:28px;letter-spacing:0}.posture-pass{color:var(--low)}.posture-review{color:var(--medium)}.posture-blocked{color:var(--critical)}.severity-bar{display:flex;height:14px;overflow:hidden;border-radius:999px;background:#e5e7eb}.segment-critical{background:var(--critical)}.segment-high{background:var(--high)}.segment-medium{background:var(--medium)}.segment-low{background:var(--low)}table{border-collapse:collapse;width:100%;background:#fff;table-layout:auto}th,td{border-bottom:1px solid var(--line);padding:9px;text-align:left;vertical-align:top;overflow-wrap:anywhere;word-break:break-word}th{background:#eef2f7;font-size:12px;text-transform:uppercase;color:#44546a}.status-block{color:var(--critical);font-weight:800}.status-warn{color:var(--medium);font-weight:800}.sev-critical{color:var(--critical);font-weight:800}.sev-high{color:var(--high);font-weight:800}.sev-medium{color:var(--medium);font-weight:800}.sev-low{color:var(--low);font-weight:800}.badge.owasp{background:#e7f0ff;color:#174ea6}.badge.nist{background:#edf7ee;color:#216e39}.badge.mitre{background:#fff4e5;color:#8a4b00}.badge.saif{background:#f2ecff;color:#5b3aa4}.muted{color:var(--muted)}summary{font-weight:800;cursor:pointer}.detail-grid{display:grid;grid-template-columns:minmax(120px,180px) 1fr;gap:8px;margin-top:12px}.detail-grid dt{font-weight:800;color:#44546a}.detail-grid dd{margin:0;overflow-wrap:anywhere}.appendix{overflow-x:auto}.nowrap{white-space:nowrap}@media(max-width:720px){main{padding:12px}header.hero{border-radius:0;margin:-12px -12px 12px}.detail-grid{grid-template-columns:1fr}.grid{grid-template-columns:1fr}table{font-size:13px}}</style>",
    "</head>",
    "<body>",
    "<main>",
    "<header class=\"hero\">",
    "<h1>VibeGuard Executive Security Report</h1>",
    `<p>Decision-oriented summary for ${escapeHtml(report.summary.targetPath || ".")}.</p>`,
    "<div class=\"meta\">",
    `<span class=\"pill\">Target: ${escapeHtml(report.summary.targetPath || ".")}</span>`,
    `<span class=\"pill\">Mode: ${escapeHtml(report.summary.scanMode)}</span>`,
    `<span class=\"pill\">Duration: ${report.summary.durationMs}ms</span>`,
    `<span class=\"pill\">Generated: ${escapeHtml(generatedAt)}</span>`,
    "</div>",
    "</header>",
    "<section class=\"panel\">",
    "<h2>Executive Summary</h2>",
    `<p><strong>${escapeHtml(derivedSummary.mergeRecommendation)}</strong>. ${executiveSummarySentence(derivedSummary, report)}</p>`,
    "<div class=\"grid\">",
    renderMetricCard("Risk Posture", derivedSummary.overallPosture.toUpperCase(), `posture-${derivedSummary.overallPosture}`),
    renderMetricCard("Merge Decision", derivedSummary.mergeRecommendation, `posture-${derivedSummary.overallPosture}`),
    renderMetricCard("Business Risk", derivedSummary.businessRiskLevel.toUpperCase(), `sev-${derivedSummary.businessRiskLevel}`),
    renderMetricCard("Owner Suggestion", derivedSummary.ownerSuggestion, ""),
    "</div>",
    "</section>",
    "<section class=\"panel\">",
    "<h2>Scan Coverage</h2>",
    `<p>Status: <strong>${escapeHtml(report.coverage.coverageStatus)}</strong> | Coverage: ${report.coverage.coveragePercent}% | Discovered: ${report.coverage.filesDiscovered} | Scanned: ${report.coverage.filesScanned} | Skipped: ${report.coverage.filesSkipped} | Policy-excluded: ${report.coverage.filesExcludedByPolicy}</p>`,
    "</section>",
    "<section class=\"panel\">",
    "<h2>Severity Distribution</h2>",
    renderSeverityBar(derivedSummary.severityDistribution),
    `<p class=\"muted\">Critical: ${derivedSummary.severityDistribution.critical} | High: ${derivedSummary.severityDistribution.high} | Medium: ${derivedSummary.severityDistribution.medium} | Low: ${derivedSummary.severityDistribution.low}</p>`,
    "</section>",
    "<section class=\"panel\">",
    "<h2>Recommended Actions</h2>",
    "<p class=\"muted\">Recommended Next Actions</p>",
    renderRecommendationTable(recommendations),
    "</section>",
    "<section class=\"panel\">",
    "<h2>Control Mappings</h2>",
    "<h3>OWASP LLM Mapping</h3>",
    renderOwaspBadges(owaspSummary),
    "<h3>GRC Risk Mapping</h3>",
    renderGrcBadges(grcRisks),
    "</section>",
    "<section class=\"panel\">",
    "<h2>AI BOM Governance</h2>",
    report.aiGovernance
      ? `<p>Added: ${report.aiGovernance.summary.added} | Removed: ${report.aiGovernance.summary.removed} | Changed: ${report.aiGovernance.summary.changed} | Unauthorized: ${report.aiGovernance.summary.unauthorized} | Blocked capabilities: ${report.aiGovernance.summary.blockedCapabilities} | Blocking: ${report.aiGovernance.summary.blocking}</p>`
      : "<p>AI BOM governance was not evaluated.</p>",
    report.aiGovernance && report.aiGovernance.violations.length > 0
      ? `<table><thead><tr><th>Status</th><th>Severity</th><th>Asset</th><th>Location</th><th>Reason</th></tr></thead><tbody>${report.aiGovernance.violations.map((violation) => `<tr><td>${violation.blocking ? "BLOCK" : "AUDIT"}</td><td>${escapeHtml(violation.severity)}</td><td>${escapeHtml(`${violation.assetKind}:${violation.assetName}`)}</td><td>${escapeHtml(`${violation.file}:${violation.line}`)}</td><td>${escapeHtml(violation.reason)}</td></tr>`).join("")}</tbody></table>`
      : "<p>No AI BOM governance violations detected.</p>",
    "</section>",
    "<section class=\"panel\">",
    "<h2>Finding Details</h2>",
    ...(report.findings.length === 0
      ? ["<p>No findings.</p>"]
      : sortFindingsForDecision(report.findings).map(renderFindingDetails)),
    "</section>",
    "<section class=\"panel appendix\">",
    "<h2>Technical Appendix</h2>",
    "<table>",
    "<thead><tr><th>Status</th><th>Severity</th><th>Confidence</th><th>Scanner</th><th>OWASP</th><th>Rule</th><th>Location</th><th>Evidence</th><th>Attack path</th><th>Impact</th><th>Suggested fix</th></tr></thead>",
    "<tbody>",
    ...sortFindingsForDecision(report.findings).map(renderTechnicalRow),
    "</tbody>",
    "</table>",
    "</section>",
    "</main>",
    "</body>",
    "</html>"
  ].join("\n");
}

function executiveSummarySentence(summary: DerivedReportSummary, report: CheckResult): string {
  if (summary.overallPosture === "pass") {
    return `No blocking findings were detected across ${report.summary.filesScanned} scanned files.`;
  }
  if (summary.overallPosture === "blocked") {
    return `${report.summary.blocking} blocking finding${report.summary.blocking === 1 ? "" : "s"} require remediation or explicit acceptance before merge.`;
  }
  return `${report.summary.findings} finding${report.summary.findings === 1 ? "" : "s"} should be reviewed before merge.`;
}

function renderMetricCard(label: string, value: string, valueClass: string): string {
  return [
    "<div class=\"card\">",
    `<span class=\"muted\">${escapeHtml(label)}</span>`,
    `<strong class=\"${escapeHtml(valueClass)}\">${escapeHtml(value)}</strong>`,
    "</div>"
  ].join("");
}

function renderSeverityBar(distribution: SeverityDistribution): string {
  const total = Math.max(1, distribution.critical + distribution.high + distribution.medium + distribution.low);
  return [
    "<div class=\"severity-bar\" aria-label=\"Severity Distribution\">",
    ...(["critical", "high", "medium", "low"] as Severity[]).map((severity) => {
      const width = distribution[severity] === 0 ? 0 : Math.max(4, Math.round((distribution[severity] / total) * 100));
      return `<span class=\"segment-${severity}\" title=\"${severity}: ${distribution[severity]}\" style=\"width:${width}%\"></span>`;
    }),
    "</div>"
  ].join("");
}

function renderRecommendationTable(recommendations: ReportRecommendation[]): string {
  if (recommendations.length === 0) return "<p>No action needed.</p>";
  return [
    "<table>",
    "<thead><tr><th>Priority</th><th>Action</th><th>Location</th><th>Fix</th></tr></thead>",
    "<tbody>",
    ...recommendations.map((recommendation) => [
      "<tr>",
      `<td class=\"sev-${recommendation.priority}\">${escapeHtml(recommendation.priority)}</td>`,
      `<td>${escapeHtml(recommendation.title)}</td>`,
      `<td>${escapeHtml(`${recommendation.file}:${recommendation.line}`)}</td>`,
      `<td>${escapeHtml(recommendation.suggestedFix)}</td>`,
      "</tr>"
    ].join("")),
    "</tbody>",
    "</table>"
  ].join("");
}

function renderOwaspBadges(summary: ReturnType<typeof summarizeOwaspFindings>): string {
  if (summary.length === 0) return "<p>No OWASP LLM mapped findings.</p>";
  return [
    "<div class=\"meta\">",
    ...summary.map((entry) => `<span class=\"badge owasp\">${escapeHtml(`${entry.id} ${entry.name}`)}: ${entry.count}</span>`),
    "</div>"
  ].join("");
}

function renderGrcBadges(risks: GrcRiskEntry[]): string {
  if (risks.length === 0) return "<p>No GRC risk mapped findings.</p>";
  return [
    "<div class=\"grid\">",
    ...risks.map((risk) => {
      const frameworks = risk.frameworks.map((framework) => `<span class=\"badge ${frameworkClass(framework.framework)}\">${escapeHtml(`${framework.framework}:${framework.id}`)}</span>`).join(" ");
      const gaps = risk.controlGaps.length
        ? risk.controlGaps.map((gap) => `<span class=\"badge\">${escapeHtml(gap)}</span>`).join(" ")
        : "<span class=\"badge\">No mapped control gaps</span>";
      return [
        "<div class=\"card\">",
        `<strong>${escapeHtml(risk.category)}</strong>`,
        `<p>Highest severity: <span class=\"sev-${risk.highestSeverity}\">${escapeHtml(risk.highestSeverity)}</span></p>`,
        `<p>Findings: ${risk.technicalEvidence.length}</p>`,
        `<p>${frameworks || "<span class=\"badge\">No framework mapping</span>"}</p>`,
        `<p>${gaps}</p>`,
        "</div>"
      ].join("");
    }),
    "</div>"
  ].join("");
}

function renderFindingDetails(finding: Finding): string {
  const status = finding.blocking ? "BLOCK" : "WARN";
  const frameworks = finding.frameworks?.length
    ? finding.frameworks.map((framework) => `<span class=\"badge ${frameworkClass(framework.framework)}\">${escapeHtml(`${framework.framework}:${framework.id}`)}</span>`).join(" ")
    : "<span class=\"badge\">No framework mapping</span>";
  return [
    "<details>",
    `<summary><span class=\"status-${status.toLowerCase()}\">${status}</span> <span class=\"sev-${finding.severity}\">${escapeHtml(finding.severity)}</span> ${escapeHtml(finding.title)} <span class=\"muted\">${escapeHtml(`${finding.file}:${finding.line}`)}</span></summary>`,
    "<dl class=\"detail-grid\">",
    "<dt>Evidence</dt>",
    `<dd>${escapeHtml(finding.evidence ?? finding.snippet)}</dd>`,
    "<dt>Attack path</dt>",
    `<dd>${escapeHtml(finding.attackPath ?? finding.why)}</dd>`,
    "<dt>Impact</dt>",
    `<dd>${escapeHtml(finding.impact ?? finding.why)}</dd>`,
    "<dt>Suggested fix</dt>",
    `<dd>${escapeHtml(finding.suggestedFix)}</dd>`,
    "<dt>Control gaps</dt>",
    `<dd>${(finding.controlGaps ?? []).map((gap) => `<span class=\"badge\">${escapeHtml(gap)}</span>`).join(" ") || "None mapped"}</dd>`,
    "<dt>Frameworks</dt>",
    `<dd>${frameworks}</dd>`,
    "</dl>",
    "</details>"
  ].join("");
}

function renderTechnicalRow(finding: Finding): string {
  const status = finding.blocking ? "BLOCK" : "WARN";
  const cells = [
    `<span class=\"status-${status.toLowerCase()}\">${status}</span>`,
    `<span class=\"sev-${finding.severity}\">${finding.severity}</span>`,
    finding.confidence,
    finding.scanner ?? "unknown",
    finding.owasp ? `${finding.owasp.id} ${finding.owasp.name}` : "Code Security",
    finding.ruleId,
    `${finding.file}:${finding.line}`,
    finding.evidence ?? finding.snippet,
    finding.attackPath ?? finding.why,
    finding.impact ?? finding.why,
    finding.suggestedFix
  ];
  return `<tr>${cells.map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`;
}

function frameworkClass(framework: string): string {
  if (framework === "owasp-llm-2025") return "owasp";
  if (framework === "nist-ai-rmf") return "nist";
  if (framework === "mitre-atlas") return "mitre";
  if (framework === "google-saif") return "saif";
  return "";
}

export function renderFindings(reportLike: ReportLike, format = "table"): string {
  if (isAiBomReport(reportLike)) {
    if (format === "aibom-json") return renderAiBomJson(reportLike.bom);
    if (format === "aibom-markdown") return renderAiBomMarkdown(reportLike.bom);
    return renderAiBomConsole(reportLike.bom);
  }
  if (isAiBomDiffReport(reportLike)) {
    if (format === "json") return JSON.stringify(reportLike.diff, null, 2);
    if (format === "risk-json") {
      return JSON.stringify({
        tool: "vibeguard",
        version: "0.1.0",
        reportType: "aibom-governance-risk",
        aiGovernance: reportLike.diff
      }, null, 2);
    }
    if (format === "markdown") return renderAiBomDiffMarkdown(reportLike.diff);
    if (format === "html") return renderAiBomDiffHtml(reportLike.diff);
    return renderAiBomDiffConsole(reportLike.diff);
  }
  if (isAgentGraphReport(reportLike)) {
    if (format === "graph-json") return renderAgentGraphJson(reportLike.graph);
    if (format === "graph-markdown") return renderAgentGraphMarkdown(reportLike.graph);
    return renderAgentGraphConsole(reportLike.graph);
  }
  if (format === "json") return renderJson(reportLike);
  if (format === "risk-json") return renderRiskJson(reportLike);
  if (format === "sarif") return renderSarif(reportLike);
  if (format === "markdown") return renderMarkdown(reportLike);
  if (format === "html") return renderHtml(reportLike);
  return renderTable(reportLike);
}

export function renderAiBomJson(bom: AiBom): string {
  return JSON.stringify(bom, null, 2);
}

export function renderAiBomConsole(bom: AiBom): string {
  const assets = allBomAssets(bom);
  const visibleAssets = assets.slice(0, 20);
  return [
    ...renderModuleHeader("AI Bill Of Materials", "Inventory of AI providers, models, prompts, agents, tools, stores, and MCP servers."),
    sectionTitle("Inventory Scope"),
    `Target: ${displayText(bom.targetPath)}`,
    `Assets discovered: ${assets.length}`,
    `High-risk capabilities: ${bom.summary.highRiskCapabilities.join(", ") || "none"}`,
    "",
    sectionTitle("Asset Counts"),
    ...renderConsoleTable(
      ["Providers", "Models", "Prompts", "Agents", "Tools", "Vector stores", "MCP servers", "Data stores"],
      [[
        String(bom.summary.providers),
        String(bom.summary.models),
        String(bom.summary.prompts),
        String(bom.summary.agents),
        String(bom.summary.tools),
        String(bom.summary.vectorStores),
        String(bom.summary.mcpServers),
        String(bom.summary.dataStores)
      ]],
      [9, 7, 7, 7, 7, 13, 11, 11]
    ),
    "",
    sectionTitle("Asset Register"),
    ...(visibleAssets.length === 0
      ? ["No AI assets detected in the selected target."]
      : renderConsoleTable(
        ["Kind", "Name", "Confidence", "Location", "Capabilities"],
        visibleAssets.map((asset) => [
          asset.kind,
          asset.name,
          asset.confidence,
          `${asset.file}:${asset.line}`,
          asset.capabilities.join(", ") || "none"
        ]),
        [14, 28, 10, 32, 42]
      )),
    ...(assets.length > visibleAssets.length
      ? ["", `Showing ${visibleAssets.length} of ${assets.length} assets. Use aibom-json for full output.`]
      : []),
    ""
  ].join("\n");
}

export function renderAiBomDiffConsole(diff: AiBomDiffResult): string {
  return [
    ...renderModuleHeader("AI BOM Governance", "Approved AI BOM drift and policy evaluation."),
    sectionTitle("Summary"),
    ...renderConsoleTable(
      ["Added", "Removed", "Changed", "Unauthorized", "Blocked Capabilities", "Blocking"],
      [[
        String(diff.summary.added),
        String(diff.summary.removed),
        String(diff.summary.changed),
        String(diff.summary.unauthorized),
        String(diff.summary.blockedCapabilities),
        String(diff.summary.blocking)
      ]],
      [7, 9, 9, 14, 22, 10]
    ),
    "",
    sectionTitle("Violations"),
    ...(diff.violations.length === 0
      ? ["No AI BOM governance violations detected."]
      : renderConsoleTable(
        ["Status", "Severity", "Asset", "Location", "Reason"],
        diff.violations.slice(0, 20).map((violation) => [
          violation.blocking ? "BLOCK" : "AUDIT",
          violation.severity,
          `${violation.assetKind}:${violation.assetName}`,
          `${violation.file}:${violation.line}`,
          violation.reason
        ]),
        [8, 9, 30, 28, 48]
      )),
    ""
  ].join("\n");
}

export function renderAiBomDiffMarkdown(diff: AiBomDiffResult): string {
  return [
    "## VibeGuard AI BOM Governance",
    "",
    `- Added: ${diff.summary.added}`,
    `- Removed: ${diff.summary.removed}`,
    `- Changed: ${diff.summary.changed}`,
    `- Unauthorized: ${diff.summary.unauthorized}`,
    `- Blocked capabilities: ${diff.summary.blockedCapabilities}`,
    `- Blocking: ${diff.summary.blocking}`,
    "",
    "### Violations",
    "",
    ...(diff.violations.length === 0
      ? ["No AI BOM governance violations detected."]
      : diff.violations.map((violation) => `- ${violation.blocking ? "BLOCK" : "AUDIT"} ${violation.severity}: ${escapeMarkdown(violation.assetKind)} ${escapeMarkdown(violation.assetName)} at ${escapeMarkdown(violation.file)}:${violation.line} - ${escapeMarkdown(violation.reason)}`)),
    ""
  ].join("\n");
}

export function renderAiBomDiffHtml(diff: AiBomDiffResult): string {
  return [
    "<!doctype html><html><head><meta charset=\"utf-8\"><title>VibeGuard AI BOM Governance</title></head><body>",
    "<h1>VibeGuard AI BOM Governance</h1>",
    "<h2>Summary</h2>",
    "<table><thead><tr><th>Added</th><th>Removed</th><th>Changed</th><th>Unauthorized</th><th>Blocked capabilities</th><th>Blocking</th></tr></thead>",
    `<tbody><tr><td>${diff.summary.added}</td><td>${diff.summary.removed}</td><td>${diff.summary.changed}</td><td>${diff.summary.unauthorized}</td><td>${diff.summary.blockedCapabilities}</td><td>${diff.summary.blocking}</td></tr></tbody></table>`,
    "<h2>Violations</h2>",
    diff.violations.length === 0
      ? "<p>No AI BOM governance violations detected.</p>"
      : `<table><thead><tr><th>Status</th><th>Severity</th><th>Asset</th><th>Location</th><th>Reason</th></tr></thead><tbody>${diff.violations.map((violation) => `<tr><td>${violation.blocking ? "BLOCK" : "AUDIT"}</td><td>${escapeHtml(violation.severity)}</td><td>${escapeHtml(`${violation.assetKind}:${violation.assetName}`)}</td><td>${escapeHtml(`${violation.file}:${violation.line}`)}</td><td>${escapeHtml(violation.reason)}</td></tr>`).join("")}</tbody></table>`,
    "</body></html>"
  ].join("");
}

export function renderAiBomMarkdown(bom: AiBom): string {
  const assets = allBomAssets(bom);
  const visibleAssets = assets.slice(0, 30);
  return [
    "## VibeGuard AI Bill of Materials",
    "",
    `Target: ${escapeMarkdown(bom.targetPath)}`,
    `- Providers: ${bom.summary.providers}`,
    `- Models: ${bom.summary.models}`,
    `- Prompts: ${bom.summary.prompts}`,
    `- Agents: ${bom.summary.agents}`,
    `- Tools: ${bom.summary.tools}`,
    `- Vector stores: ${bom.summary.vectorStores}`,
    `- MCP servers: ${bom.summary.mcpServers}`,
    `- High-risk capabilities: ${bom.summary.highRiskCapabilities.join(", ") || "none"}`,
    "",
    "### Assets",
    "",
    ...(visibleAssets.length === 0
      ? ["- No AI assets detected in the selected target."]
      : visibleAssets.map((asset) =>
        `- ${asset.kind}: ${escapeMarkdown(asset.name)} (${escapeMarkdown(asset.file)}:${asset.line}) confidence=${asset.confidence} capabilities=${asset.capabilities.join(",") || "none"}`
      )),
    ...(assets.length > visibleAssets.length
      ? ["", `Showing ${visibleAssets.length} of ${assets.length} assets. Use --format aibom-json for complete machine-readable output.`]
      : []),
    ""
  ].join("\n");
}

export function renderAgentGraphJson(graph: AgentCapabilityGraph): string {
  return JSON.stringify(graph, null, 2);
}

export function renderAgentGraphConsole(graph: AgentCapabilityGraph): string {
  return [
    ...renderModuleHeader("Agent Capability Graph", "Reachability view of agent tools, high-risk capabilities, and control boundaries."),
    sectionTitle("Exposure Summary"),
    `Target: ${displayText(graph.targetPath)}`,
    `High-risk paths: ${graph.summary.highRiskPaths}`,
    "",
    ...renderConsoleTable(
      ["Agents", "Tools", "Capabilities", "High-risk paths"],
      [[
        String(graph.summary.agents),
        String(graph.summary.tools),
        String(graph.summary.capabilities),
        String(graph.summary.highRiskPaths)
      ]],
      [7, 7, 12, 15]
    ),
    "",
    sectionTitle("High-Risk Paths"),
    ...(graph.risks.length === 0
      ? ["None detected in the selected target."]
      : renderConsoleTable(
        ["Severity", "Risk", "Strength", "Evidence", "Fix"],
        graph.risks.map((risk) => [
          risk.severity,
          risk.title,
          risk.evidenceStrength,
          risk.evidence,
          risk.suggestedFix
        ]),
        [9, 34, 19, 52, 52]
      )),
    "",
    sectionTitle("Access Paths"),
    ...renderAccessDiagram(graph),
    ""
  ].join("\n");
}

export function renderAgentGraphMarkdown(graph: AgentCapabilityGraph): string {
  const visibleEdges = graph.edges.slice(0, 30);
  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  return [
    "## VibeGuard Agent Capability Graph",
    "",
    `Target: ${escapeMarkdown(graph.targetPath)}`,
    `- Agents: ${graph.summary.agents}`,
    `- Tools: ${graph.summary.tools}`,
    `- Capabilities: ${graph.summary.capabilities}`,
    `- High-risk paths: ${graph.summary.highRiskPaths}`,
    "",
    "### Access Diagram",
    "",
    ...renderAccessDiagram(graph).map(escapeMarkdown),
    "",
    "### Mermaid Diagram",
    "",
    ...renderMermaidDiagram(graph),
    "",
    "### High-Risk Paths",
    "",
    ...(graph.risks.length === 0
      ? ["- None detected in the selected target."]
      : graph.risks.map((risk) => `- ${risk.severity}: ${escapeMarkdown(risk.title)} evidence=${risk.evidenceStrength}. ${escapeMarkdown(risk.evidence)} Fix: ${escapeMarkdown(risk.suggestedFix)}`)),
    "",
    "### Edges",
    "",
    ...(visibleEdges.length === 0
      ? ["- No agent, tool, or capability edges detected."]
      : visibleEdges.map((edge) => `- ${escapeMarkdown(edgeEndpointLabel(nodes, edge.from))} ${edge.relation} ${escapeMarkdown(edgeEndpointLabel(nodes, edge.to))}${edge.capability ? ` (${edge.capability})` : ""} evidence=${edge.evidenceStrength}`)),
    ...(graph.edges.length > visibleEdges.length
      ? ["", `Showing ${visibleEdges.length} of ${graph.edges.length} edges. Use --format graph-json for complete machine-readable output.`]
      : []),
    ""
  ].join("\n");
}

function isAiBomReport(value: ReportLike): value is AiBomReportLike {
  return !Array.isArray(value) && "kind" in value && value.kind === "aibom";
}

function isAiBomDiffReport(value: ReportLike): value is AiBomDiffReportLike {
  return !Array.isArray(value) && "kind" in value && value.kind === "aibom-diff";
}

function isAgentGraphReport(value: ReportLike): value is AgentGraphReportLike {
  return !Array.isArray(value) && "kind" in value && value.kind === "graph";
}

function allBomAssets(bom: AiBom): AiAsset[] {
  return [
    ...bom.providers,
    ...bom.models,
    ...bom.prompts,
    ...bom.agents,
    ...bom.tools,
    ...bom.vectorStores,
    ...bom.mcpServers,
    ...bom.dataStores
  ];
}

function renderAccessDiagram(graph: AgentCapabilityGraph): string[] {
  if (graph.nodes.length === 0 || graph.edges.length === 0) {
    return ["No AI access paths detected in the selected target."];
  }

  const nodes = new Map(graph.nodes.map((node) => [node.id, node]));
  const outgoing = graph.edges.reduce<Map<string, typeof graph.edges>>((accumulator, edge) => {
    accumulator.set(edge.from, [...(accumulator.get(edge.from) ?? []), edge]);
    return accumulator;
  }, new Map());
  const agentRoots = graph.nodes.filter((node) => node.kind === "agent" && (outgoing.get(node.id)?.length ?? 0) > 0);
  const roots = agentRoots.length
    ? agentRoots
    : graph.nodes.filter((node) => node.kind !== "capability" && (outgoing.get(node.id)?.length ?? 0) > 0);

  const lines: string[] = [];
  for (const root of roots.slice(0, 12)) {
    lines.push(`${nodeLabel(root)}${riskSuffix(graph, root.id)}`);
    for (const edge of (outgoing.get(root.id) ?? []).slice(0, 10)) {
      const to = nodes.get(edge.to);
      lines.push(`  -> ${edge.relation}${edge.capability ? `:${edge.capability}` : ""} [${edge.evidenceStrength}] -> ${to ? nodeLabel(to) : edge.to}${riskSuffix(graph, edge.to)}`);
      for (const next of (outgoing.get(edge.to) ?? []).slice(0, 8)) {
        const nextNode = nodes.get(next.to);
        lines.push(`       -> ${next.relation}${next.capability ? `:${next.capability}` : ""} [${next.evidenceStrength}] -> ${nextNode ? nodeLabel(nextNode) : next.to}${riskSuffix(graph, next.to)}`);
      }
    }
    lines.push("");
  }

  if (roots.length > 12) lines.push(`Showing 12 of ${roots.length} access roots. Use --format graph-json for full output.`);
  return lines.length ? lines : ["No AI access paths detected in the selected target."];
}

function renderMermaidDiagram(graph: AgentCapabilityGraph): string[] {
  if (graph.nodes.length === 0 || graph.edges.length === 0) {
    return ["```mermaid", "flowchart LR", "  empty[\"No AI access paths detected\"]", "```"];
  }

  const connectedIds = new Set(graph.edges.flatMap((edge) => [edge.from, edge.to]));
  const connectedNodes = graph.nodes.filter((node) => connectedIds.has(node.id));
  const nodeIds = new Map(connectedNodes.map((node, index) => [node.id, `n${index}`]));
  const highRiskNodeIds = new Set(graph.risks.flatMap((risk) => risk.path));
  const lines = ["```mermaid", "flowchart LR"];
  for (const node of connectedNodes.slice(0, 60)) {
    lines.push(`  ${nodeIds.get(node.id)}["${escapeMermaid(`${node.kind}: ${node.label}`)}"]`);
  }
  for (const edge of graph.edges.slice(0, 80)) {
    const from = nodeIds.get(edge.from);
    const to = nodeIds.get(edge.to);
    if (!from || !to) continue;
    const label = edge.capability ? `${edge.relation}: ${edge.capability} (${edge.evidenceStrength})` : `${edge.relation} (${edge.evidenceStrength})`;
    lines.push(`  ${from} -->|"${escapeMermaid(label)}"| ${to}`);
  }
  lines.push("  classDef highRisk fill:#ffe8e8,stroke:#b42318,stroke-width:2px,color:#111827");
  for (const node of connectedNodes.filter((candidate) => highRiskNodeIds.has(candidate.id)).slice(0, 60)) {
    lines.push(`  class ${nodeIds.get(node.id)} highRisk`);
  }
  lines.push("```");
  return lines;
}

function nodeLabel(node: AgentCapabilityGraph["nodes"][number]): string {
  return `[${node.kind}] ${displayText(node.label)}${node.file ? ` (${displayText(node.file)}:${node.line})` : ""}`;
}

function edgeEndpointLabel(nodes: Map<string, AgentCapabilityGraph["nodes"][number]>, id: string): string {
  const node = nodes.get(id);
  return node ? `${node.kind}:${displayText(node.label)}` : displayText(id);
}

function riskSuffix(graph: AgentCapabilityGraph, nodeId: string): string {
  const risk = graph.risks.find((candidate) => candidate.path.includes(nodeId));
  return risk ? `  [${risk.severity.toUpperCase()} RISK]` : "";
}

function escapeMermaid(value: string): string {
  return displayText(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/\|/g, "&#124;")
    .replace(/\\/g, "\\\\")
    .replace(/"/g, "\\\"");
}

function renderModuleHeader(moduleName: string, subtitle: string): string[] {
  const title = `VIBEGUARD / ${moduleName.toUpperCase()}`;
  return [
    title,
    "=".repeat(title.length),
    subtitle,
    ""
  ];
}

function sectionTitle(title: string): string {
  return [
    title,
    "-".repeat(title.length)
  ].join("\n");
}

function renderRiskCategoryTable(risks: GrcRiskEntry[]): string[] {
  if (risks.length === 0) return ["No GRC risk categories were generated."];

  return renderConsoleTable(
    ["Category", "Severity", "Findings", "Frameworks", "Control gaps"],
    risks.map((risk) => [
      risk.category,
      risk.highestSeverity,
      String(risk.technicalEvidence.length),
      risk.frameworks.map((framework) => `${framework.framework}:${framework.id}`).join(", ") || "none",
      risk.controlGaps.join(", ") || "none"
    ]),
    [34, 9, 8, 44, 44]
  );
}

function renderFrameworkCoverage(frameworks: Array<{ framework: string; count: number }>): string[] {
  if (frameworks.length === 0) {
    return ["No framework-mapped findings. Review unmapped technical findings before treating this as low governance risk."];
  }

  return renderConsoleTable(
    ["Framework", "Mapped findings"],
    frameworks.map((framework) => [framework.framework, String(framework.count)]),
    [24, 16]
  );
}

function renderDecisionSnapshot(report: CheckResult, summary: DerivedReportSummary): string[] {
  return [
    `Result: ${summary.overallPosture.toUpperCase()}`,
    `Merge recommendation: ${summary.mergeRecommendation}`,
    `Business risk: ${summary.businessRiskLevel.toUpperCase()}`,
    `Primary owner: ${summary.ownerSuggestion}`,
    `Findings: ${report.summary.findings} total, ${report.summary.blocking} blocking`,
    `Top risk: ${summary.topRisks[0]?.title ?? "none"}`
  ];
}

function renderScanScope(report: CheckResult): string[] {
  return [
    `Target: ${displayText(report.summary.targetPath || ".")}`,
    `Mode: ${report.summary.scanMode}`,
    `Coverage: ${report.coverage.coverageStatus} (${report.coverage.coveragePercent}% scanned, ${report.summary.filesScanned} files in ${report.summary.durationMs}ms)`,
    `Skipped: ${report.coverage.filesSkipped} skipped, ${report.coverage.filesExcludedByPolicy} policy-excluded, file limit ${report.coverage.fileLimitReached ? "reached" : "not reached"}`,
    `Warnings: ${report.summary.warnings}`,
    `Baseline suppressed: ${report.summary.baselineSuppressed}`,
    `Truncated: ${report.summary.truncated ? "yes" : "no"}`
  ];
}

function renderSeverityDistribution(distribution: SeverityDistribution): string[] {
  const severities: Severity[] = ["critical", "high", "medium", "low"];
  const total = severities.reduce((sum, severity) => sum + distribution[severity], 0);

  return severities.map((severity) => {
    const count = distribution[severity];
    return `${severity.toUpperCase().padEnd(8)} ${String(count).padStart(3)} ${renderAsciiBar(count, total)}`;
  });
}

function renderAsciiBar(count: number, total: number): string {
  const width = 24;
  const filled = total === 0 ? 0 : Math.max(count > 0 ? 1 : 0, Math.round((count / total) * width));
  return `[${"#".repeat(filled)}${".".repeat(width - filled)}]`;
}

function renderPriorityActionPlan(summary: DerivedReportSummary): string[] {
  if (summary.topRisks.length === 0) return ["No action needed."];

  return renderConsoleTable(
    ["#", "Priority", "Owner", "Location", "Required action"],
    summary.topRisks.slice(0, 5).map((risk, index) => [
      String(index + 1),
      risk.blocking ? `BLOCK ${risk.severity}` : `REVIEW ${risk.severity}`,
      risk.owner,
      `${risk.file}:${risk.line}`,
      risk.suggestedFix
    ]),
    [3, 16, 12, 28, 70]
  );
}

function renderControlGapSummary(summary: DerivedReportSummary): string[] {
  if (summary.controlGapSummary.length === 0) {
    return ["No mapped control gaps. Treat unmapped findings as technical risk until ownership is assigned."];
  }

  return renderConsoleTable(
    ["Control gap", "Count", "Suggested owner"],
    summary.controlGapSummary.map((gap) => [
      gap.gap,
      String(gap.count),
      gap.owner
    ]),
    [48, 7, 18]
  );
}

function renderTopRiskTable(summary: DerivedReportSummary): string[] {
  if (summary.topRisks.length === 0) return ["No top risks."];

  return renderConsoleTable(
    ["#", "Score", "Severity", "Rule", "Location", "Business impact"],
    summary.topRisks.map((risk, index) => [
      String(index + 1),
      String(risk.riskScore),
      risk.severity,
      risk.ruleId,
      `${risk.file}:${risk.line}`,
      risk.impact ?? "Review technical evidence."
    ]),
    [3, 5, 9, 32, 28, 60]
  );
}

function renderConsoleTable(headers: string[], rows: string[][], maxWidths: number[]): string[] {
  const clippedRows = rows.map((row) => row.map((cell, index) => clipConsoleCell(cell, maxWidths[index] ?? 48)));
  const clippedHeaders = headers.map((header, index) => clipConsoleCell(header, maxWidths[index] ?? 48));
  const widths = clippedHeaders.map((header, index) =>
    Math.max(header.length, ...clippedRows.map((row) => row[index]?.length ?? 0))
  );
  const renderRow = (row: string[]) => row
    .map((cell, index) => (cell ?? "").padEnd(widths[index]))
    .join("  ");

  return [
    renderRow(clippedHeaders),
    renderRow(widths.map((width) => "-".repeat(width))),
    ...clippedRows.map(renderRow)
  ];
}

function clipConsoleCell(value: string, maxWidth: number): string {
  const text = displayText(value).trim();
  if (text.length <= maxWidth) return text;
  if (maxWidth <= 3) return text.slice(0, maxWidth);
  return `${text.slice(0, maxWidth - 3)}...`;
}

function renderFindingCard(finding: Finding, index: number): string {
  return [
    `[${index}] ${finding.blocking ? "BLOCK" : "WARN"} | ${finding.severity.toUpperCase()} | risk ${finding.riskScore} | ${displayText(finding.title)}`,
    `    Rule: ${displayText(finding.ruleId)}${finding.scanner ? ` (${finding.scanner})` : ""}`,
    `    Location: ${displayText(finding.file)}:${finding.line}`,
    `    Evidence: ${clipConsoleCell(finding.evidence ?? finding.snippet, 110)}`,
    `    Attack path: ${clipConsoleCell(finding.attackPath ?? finding.why, 110)}`,
    `    Impact: ${clipConsoleCell(finding.impact ?? finding.why, 110)}`,
    `    Fix: ${clipConsoleCell(finding.suggestedFix, 110)}`,
    finding.frameworks?.length
      ? `    Frameworks: ${finding.frameworks.map((framework) => `${framework.framework}:${framework.id}`).join(", ")}`
      : "    Frameworks: none mapped",
    ""
  ].join("\n");
}

function buildGrcRisks(findings: Finding[]): GrcRiskEntry[] {
  return [...findings.reduce<Map<string, Finding[]>>((accumulator, finding) => {
    const category = finding.risk?.category ?? UNMAPPED_GRC_RISK_CATEGORY;
    accumulator.set(category, [...(accumulator.get(category) ?? []), finding]);
    return accumulator;
  }, new Map()).entries()]
    .map(([category, groupedFindings]) => {
      const frameworks = uniqueFrameworks(groupedFindings);
      const controlGaps = [...new Set(groupedFindings.flatMap((finding) => finding.controlGaps ?? []))].sort();
      return {
        category,
        highestSeverity: groupedFindings.reduce(
          (highest, finding) => {
            const severity = finding.risk?.severity ?? finding.severity;
            return severityRank(severity) > severityRank(highest) ? severity : highest;
          },
          groupedFindings[0].risk?.severity ?? groupedFindings[0].severity
        ),
        frameworks,
        controlGaps,
        technicalEvidence: groupedFindings.map((finding) => ({
          id: finding.id,
          ruleId: finding.ruleId,
          ruleVersion: finding.rule?.version,
          title: finding.title,
          severity: finding.severity,
          confidence: finding.confidence,
          evidenceStrength: finding.evidenceStrength,
          evidenceSource: finding.evidenceSource,
          detectionMethod: finding.detectionMethod,
          relatedLocations: finding.relatedLocations ?? [],
          file: finding.file,
          line: finding.line,
          snippet: finding.snippet,
          evidence: finding.evidence ?? finding.snippet,
          scanner: finding.scanner ?? finding.rule?.scanner ?? "unknown",
          impact: finding.impact ?? finding.why,
          suggestedFix: finding.suggestedFix,
          blocking: finding.blocking
        }))
      };
    })
    .sort((left, right) =>
      severityRank(right.highestSeverity) - severityRank(left.highestSeverity)
      || left.category.localeCompare(right.category)
    );
}

function uniqueFrameworks(findings: Finding[]): NonNullable<Finding["frameworks"]> {
  return [...new Map(
    findings
      .flatMap((finding) => finding.frameworks ?? [])
      .map((framework) => [`${framework.framework}\0${framework.id}\0${framework.name}\0${framework.sourceVersion}`, framework])
  ).values()].sort((left, right) =>
    left.framework.localeCompare(right.framework)
    || left.id.localeCompare(right.id)
  );
}

export function buildRecommendations(reportLike: ScanReportLike, limit = 5): ReportRecommendation[] {
  const report = normalizeReport(reportLike);
  return [...report.findings]
    .sort((left, right) =>
      Number(right.blocking) - Number(left.blocking)
      || severityRank(right.severity) - severityRank(left.severity)
      || right.riskScore - left.riskScore
      || left.file.localeCompare(right.file)
      || left.line - right.line
    )
    .slice(0, limit)
    .map((finding) => ({
      title: `Fix ${finding.title}`,
      priority: finding.severity,
      ruleId: finding.ruleId,
      file: finding.file,
      line: finding.line,
      suggestedFix: finding.suggestedFix,
      aiFixPrompt: finding.aiFixPrompt,
      owasp: finding.owasp,
      attackPath: finding.attackPath,
      impact: finding.impact,
      blocking: finding.blocking
    }));
}

function summarize(findings: Finding[], existing?: CheckResult["summary"]) {
  return {
    filesChanged: existing?.filesChanged ?? 0,
    filesScanned: existing?.filesScanned ?? 0,
    findings: findings.length,
    blocking: findings.filter((finding) => finding.blocking).length,
    truncated: existing?.truncated ?? false,
    durationMs: existing?.durationMs ?? 0,
    scanMode: existing?.scanMode ?? "repository",
    targetPath: existing?.targetPath ?? "",
    warnings: existing?.warnings ?? 0,
    baselineSuppressed: existing?.baselineSuppressed ?? 0,
    bySeverity: findings.reduce<Record<string, number>>((accumulator, finding) => {
      accumulator[finding.severity] = (accumulator[finding.severity] ?? 0) + 1;
      return accumulator;
    }, {})
  };
}

function sarifLevel(severity: string): "note" | "warning" | "error" {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "medium") return "warning";
  return "note";
}

function displayText(value: string): string {
  return value
    .replace(/[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, "")
    .replace(/\r?\n/g, " ");
}

function escapeMarkdown(value: string): string {
  return displayText(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/([\\`*_{}\[\]()#+.!|-])/g, "\\$1");
}

function normalizeReport(reportLike: ScanReportLike): CheckResult {
  if (Array.isArray(reportLike)) {
    return {
      findings: reportLike,
      files: [],
      warnings: [],
      coverage: emptyCoverage(),
      summary: summarize(reportLike)
    };
  }
  return {
    ...reportLike,
    coverage: reportLike.coverage ?? emptyCoverage(),
    summary: summarize(reportLike.findings, reportLike.summary)
  };
}

function emptyCoverage() {
  return {
    filesDiscovered: 0,
    filesScanned: 0,
    filesSkipped: 0,
    filesExcludedByPolicy: 0,
    filesSkippedBinary: 0,
    filesSkippedOversized: 0,
    filesUnreadable: 0,
    fileLimitReached: false,
    coveragePercent: 100,
    coverageStatus: "complete" as const
  };
}

function groupBy(findings: Finding[], key: "severity" | "scanner"): Record<string, number> {
  return findings.reduce<Record<string, number>>((accumulator, finding) => {
    const value = key === "scanner" ? finding.scanner ?? "unknown" : finding.severity;
    accumulator[value] = (accumulator[value] ?? 0) + 1;
    return accumulator;
  }, {});
}

function renderScanFooter(report: CheckResult): string {
  const parts = [
    `Scanned ${report.summary.filesScanned} files`,
    `mode=${report.summary.scanMode}`,
    `target=${displayText(report.summary.targetPath || ".")}`,
    `duration=${report.summary.durationMs}ms`,
    `warnings=${report.summary.warnings}`
  ];
  if (report.summary.truncated) parts.push("truncated=true");
  if (report.summary.baselineSuppressed > 0) parts.push(`baselineSuppressed=${report.summary.baselineSuppressed}`);
  return parts.join(" | ");
}

function renderRecommendationFooter(report: CheckResult): string {
  const recommendations = buildRecommendations(report, 3);
  if (recommendations.length === 0) return "Next actions: none";
  return `Next actions: ${recommendations.map((recommendation) => `${displayText(recommendation.title)} (${displayText(recommendation.file)}:${recommendation.line})`).join("; ")}`;
}

function escapeHtml(value: string): string {
  return displayText(value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
