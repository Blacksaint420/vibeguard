import { severityRank } from "../../core/src/types.ts";
import { summarizeOwaspFindings } from "../../core/src/owasp.ts";
import { summarizeGrcRisks } from "../../core/src/risk.ts";
import type { CheckResult, Finding, ReportRecommendation } from "../../core/src/types.ts";

type ReportLike = Finding[] | CheckResult;

type GrcRiskEntry = {
  category: string;
  highestSeverity: Finding["severity"];
  frameworks: NonNullable<Finding["frameworks"]>;
  controlGaps: string[];
  technicalEvidence: Array<{
    id: string;
    ruleId: string;
    ruleVersion?: string;
    severity: Finding["severity"];
    confidence: Finding["confidence"];
    file: string;
    line: number;
    scanner: string;
    impact: string;
    suggestedFix: string;
    blocking: boolean;
  }>;
};

export function renderJson(reportLike: ReportLike): string {
  const report = normalizeReport(reportLike);
  return JSON.stringify(
    {
      tool: "vibeguard",
      version: "0.1.0",
      summary: report.summary,
      owaspSummary: summarizeOwaspFindings(report.findings),
      warnings: report.warnings,
      recommendations: buildRecommendations(report),
      findings: report.findings
    },
    null,
    2
  );
}

export function renderRiskJson(reportLike: ReportLike): string {
  const report = normalizeReport(reportLike);
  return JSON.stringify(
    {
      tool: "vibeguard",
      version: "0.1.0",
      reportType: "grc-risk",
      summary: report.summary,
      riskSummary: summarizeGrcRisks(report.findings),
      risks: buildGrcRisks(report.findings)
    },
    null,
    2
  );
}

export function renderTable(reportLike: ReportLike): string {
  const report = normalizeReport(reportLike);
  const findings = report.findings;
  if (findings.length === 0) {
    return [
      "VibeGuard: no findings.",
      renderScanFooter(report),
      ""
    ].join("\n");
  }

  const rows = findings.map((finding) => [
    finding.blocking ? "BLOCK" : "WARN",
    finding.severity,
    finding.confidence,
    String(finding.riskScore),
    finding.file,
    String(finding.line),
    finding.owasp ? `${finding.owasp.id} ${finding.owasp.name}` : "Code Security",
    finding.ruleId,
    finding.scanner ?? "unknown",
    finding.impact ?? finding.why
  ]);
  const header = ["status", "severity", "confidence", "risk", "file", "line", "owasp", "rule", "scanner", "impact"];
  const widths = header.map((name, index) =>
    Math.max(name.length, ...rows.map((row) => row[index].length))
  );

  const renderRow = (row: string[]) => row.map((cell, index) => cell.padEnd(widths[index])).join("  ");
  return [
    "VibeGuard findings",
    renderRow(header),
    renderRow(widths.map((width) => "-".repeat(width))),
    ...rows.map(renderRow),
    renderRecommendationFooter(report),
    renderScanFooter(report),
    ""
  ].join("\n");
}

export function renderMarkdown(reportLike: ReportLike): string {
  const report = normalizeReport(reportLike);
  const findings = report.findings;
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
    `- Scan mode: ${report.summary.scanMode}`,
    `- Warnings: ${report.summary.warnings}`,
    `- Baseline suppressed: ${report.summary.baselineSuppressed}`,
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
    ""
  ];

  lines.push("### Recommended Next Actions", "");
  const recommendations = buildRecommendations(report);
  if (recommendations.length === 0) {
    lines.push("- No action needed.", "");
  } else {
    for (const recommendation of recommendations) {
      lines.push(
        `- ${recommendation.blocking ? "Blocker" : "Review"}: ${escapeMarkdown(recommendation.title)} in ${recommendation.file}:${recommendation.line}. ${escapeMarkdown(recommendation.suggestedFix)}`
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
    lines.push(`- OWASP: ${finding.owasp ? `${finding.owasp.id} ${finding.owasp.name}` : "Code Security"}`);
    lines.push(`- Location: ${finding.file}:${finding.line}`);
    lines.push(`- Evidence: ${escapeMarkdown(finding.evidence ?? finding.snippet)}`);
    lines.push(`- Attack path: ${escapeMarkdown(finding.attackPath ?? finding.why)}`);
    lines.push(`- Impact: ${escapeMarkdown(finding.impact ?? finding.why)}`);
    lines.push(`- Fix: ${escapeMarkdown(finding.suggestedFix)}`);
    lines.push("");
  }
  lines.push("");
  return lines.join("\n");
}

export function renderSarif(reportLike: ReportLike): string {
  const report = normalizeReport(reportLike);
  const findings = report.findings;
  const rules = [...new Map(findings.map((finding) => [
    finding.ruleId,
    {
      id: finding.ruleId,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.why },
      help: { text: finding.suggestedFix }
    }
  ])).values()];

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
          results: findings.map((finding) => ({
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
          }))
        }
      ]
    },
    null,
    2
  );
}

export function renderHtml(reportLike: ReportLike): string {
  const report = normalizeReport(reportLike);
  const recommendations = buildRecommendations(report);
  const owaspSummary = summarizeOwaspFindings(report.findings);
  const grcRisks = buildGrcRisks(report.findings);
  const rows = report.findings.map((finding) => [
    finding.blocking ? "BLOCK" : "WARN",
    finding.severity,
    finding.confidence,
    finding.scanner ?? "unknown",
    finding.owasp ? `${finding.owasp.id} ${finding.owasp.name}` : "Code Security",
    finding.ruleId,
    `${finding.file}:${finding.line}`,
    finding.evidence ?? finding.snippet,
    finding.attackPath ?? finding.why,
    finding.impact ?? finding.why,
    finding.suggestedFix
  ]);
  return [
    "<!doctype html>",
    "<html>",
    "<head>",
    "<meta charset=\"utf-8\">",
    "<title>VibeGuard Report</title>",
    "<style>body{font-family:system-ui,sans-serif;margin:24px;color:#1f2933;background:#fbfcfd;}main{max-width:1180px;margin:0 auto;}section{margin:20px 0;}table{border-collapse:collapse;width:100%;background:#fff;}th,td{border:1px solid #d9e2ec;padding:8px;text-align:left;vertical-align:top;}th{background:#eef2f7}.summary{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.metric{background:#fff;border:1px solid #d9e2ec;border-radius:6px;padding:12px}.metric strong{display:block;font-size:24px}.actions{background:#fff;border:1px solid #d9e2ec;border-radius:6px;padding:14px}.block{color:#b00020;font-weight:700}.warn{color:#8a5a00}</style>",
    "</head>",
    "<body>",
    "<main>",
    "<h1>VibeGuard Report</h1>",
    "<section class=\"summary\">",
    `<div class=\"metric\"><span>Findings</span><strong>${report.summary.findings}</strong></div>`,
    `<div class=\"metric\"><span>Blocking</span><strong>${report.summary.blocking}</strong></div>`,
    `<div class=\"metric\"><span>Files scanned</span><strong>${report.summary.filesScanned}</strong></div>`,
    `<div class=\"metric\"><span>Warnings</span><strong>${report.summary.warnings}</strong></div>`,
    `<div class=\"metric\"><span>Baseline suppressed</span><strong>${report.summary.baselineSuppressed}</strong></div>`,
    "</section>",
    "<section class=\"actions\">",
    "<h2>Recommended Next Actions</h2>",
    recommendations.length === 0
      ? "<p>No action needed.</p>"
      : `<ol>${recommendations.map((recommendation) => `<li><strong>${escapeHtml(recommendation.title)}</strong> in ${escapeHtml(`${recommendation.file}:${recommendation.line}`)}. ${escapeHtml(recommendation.suggestedFix)}</li>`).join("")}</ol>`,
    "</section>",
    "<section class=\"actions\">",
    "<h2>OWASP LLM Mapping</h2>",
    owaspSummary.length === 0
      ? "<p>No OWASP LLM mapped findings.</p>"
      : `<ul>${owaspSummary.map((entry) => `<li><strong>${escapeHtml(`${entry.id} ${entry.name}`)}</strong>: ${entry.count} finding${entry.count === 1 ? "" : "s"} (${entry.blocking} blocking)</li>`).join("")}</ul>`,
    "</section>",
    "<section class=\"actions\">",
    "<h2>GRC Risk Mapping</h2>",
    grcRisks.length === 0
      ? "<p>No GRC risk mapped findings.</p>"
      : `<ul>${grcRisks.map((risk) => {
        const frameworks = risk.frameworks.map((framework) => `${framework.framework}:${framework.id}`).join(", ") || "none";
        const controlGaps = risk.controlGaps.join(", ") || "none";
        return `<li><strong>${escapeHtml(risk.category)}</strong>: ${risk.technicalEvidence.length} finding${risk.technicalEvidence.length === 1 ? "" : "s"}; highest severity ${escapeHtml(risk.highestSeverity)}; frameworks ${escapeHtml(frameworks)}; control gaps ${escapeHtml(controlGaps)}</li>`;
      }).join("")}</ul>`,
    "</section>",
    "<section>",
    "<table>",
    "<thead><tr><th>Status</th><th>Severity</th><th>Confidence</th><th>Scanner</th><th>OWASP</th><th>Rule</th><th>Location</th><th>Evidence</th><th>Attack path</th><th>Impact</th><th>Suggested fix</th></tr></thead>",
    "<tbody>",
    ...rows.map((row) => `<tr><td class="${row[0] === "BLOCK" ? "block" : "warn"}">${escapeHtml(row[0])}</td>${row.slice(1).map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`),
    "</tbody>",
    "</table>",
    "</section>",
    "</main>",
    "</body>",
    "</html>"
  ].join("\n");
}

export function renderFindings(reportLike: ReportLike, format = "table"): string {
  if (format === "json") return renderJson(reportLike);
  if (format === "risk-json") return renderRiskJson(reportLike);
  if (format === "sarif") return renderSarif(reportLike);
  if (format === "markdown") return renderMarkdown(reportLike);
  if (format === "html") return renderHtml(reportLike);
  return renderTable(reportLike);
}

function buildGrcRisks(findings: Finding[]): GrcRiskEntry[] {
  return [...findings.reduce<Map<string, Finding[]>>((accumulator, finding) => {
    const category = finding.risk?.category ?? "Unmapped technical finding";
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
          severity: finding.severity,
          confidence: finding.confidence,
          file: finding.file,
          line: finding.line,
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

export function buildRecommendations(reportLike: ReportLike, limit = 5): ReportRecommendation[] {
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

function escapeMarkdown(value: string): string {
  return value.replace(/\|/g, "\\|").replace(/\n/g, " ");
}

function normalizeReport(reportLike: ReportLike): CheckResult {
  if (Array.isArray(reportLike)) {
    return {
      findings: reportLike,
      files: [],
      warnings: [],
      summary: summarize(reportLike)
    };
  }
  return {
    ...reportLike,
    summary: summarize(reportLike.findings, reportLike.summary)
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
    `target=${report.summary.targetPath || "."}`,
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
  return `Next actions: ${recommendations.map((recommendation) => `${recommendation.title} (${recommendation.file}:${recommendation.line})`).join("; ")}`;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
