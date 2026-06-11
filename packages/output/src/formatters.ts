import { severityRank } from "../../core/src/types.ts";
import type { CheckResult, Finding, ReportRecommendation } from "../../core/src/types.ts";

type ReportLike = Finding[] | CheckResult;

export function renderJson(reportLike: ReportLike): string {
  const report = normalizeReport(reportLike);
  return JSON.stringify(
    {
      tool: "vibeguard",
      version: "0.1.0",
      summary: report.summary,
      warnings: report.warnings,
      recommendations: buildRecommendations(report),
      findings: report.findings
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
    finding.ruleId,
    finding.scanner ?? "unknown",
    finding.snippet.replace(/\s+/g, " ").slice(0, 90)
  ]);
  const header = ["status", "severity", "confidence", "risk", "file", "line", "rule", "scanner", "snippet"];
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

  lines.push("| Status | Severity | Rule | Location | Why | Suggested fix |");
  lines.push("| --- | --- | --- | --- | --- | --- |");
  for (const finding of findings) {
    lines.push(
      `| ${finding.blocking ? "BLOCK" : "WARN"} | ${finding.severity} | ${finding.ruleId} | ${finding.file}:${finding.line} | ${escapeMarkdown(finding.why)} | ${escapeMarkdown(finding.suggestedFix)} |`
    );
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
  const rows = report.findings.map((finding) => [
    finding.blocking ? "BLOCK" : "WARN",
    finding.severity,
    finding.confidence,
    finding.scanner ?? "unknown",
    finding.ruleId,
    `${finding.file}:${finding.line}`,
    finding.why,
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
    "<section>",
    "<table>",
    "<thead><tr><th>Status</th><th>Severity</th><th>Confidence</th><th>Scanner</th><th>Rule</th><th>Location</th><th>Why</th><th>Suggested fix</th></tr></thead>",
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
  if (format === "sarif") return renderSarif(reportLike);
  if (format === "markdown") return renderMarkdown(reportLike);
  if (format === "html") return renderHtml(reportLike);
  return renderTable(reportLike);
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
