import type { Finding } from "../../core/src/types.ts";

export function renderJson(findings: Finding[]): string {
  return JSON.stringify(
    {
      tool: "vibeguard",
      version: "0.1.0",
      summary: summarize(findings),
      findings
    },
    null,
    2
  );
}

export function renderTable(findings: Finding[]): string {
  if (findings.length === 0) {
    return "VibeGuard: no findings in changed lines.\n";
  }

  const rows = findings.map((finding) => [
    finding.blocking ? "BLOCK" : "WARN",
    finding.severity,
    finding.confidence,
    String(finding.riskScore),
    finding.file,
    String(finding.line),
    finding.ruleId,
    finding.snippet.replace(/\s+/g, " ").slice(0, 90)
  ]);
  const header = ["status", "severity", "confidence", "risk", "file", "line", "rule", "snippet"];
  const widths = header.map((name, index) =>
    Math.max(name.length, ...rows.map((row) => row[index].length))
  );

  const renderRow = (row: string[]) => row.map((cell, index) => cell.padEnd(widths[index])).join("  ");
  return [
    "VibeGuard findings",
    renderRow(header),
    renderRow(widths.map((width) => "-".repeat(width))),
    ...rows.map(renderRow),
    ""
  ].join("\n");
}

export function renderMarkdown(findings: Finding[]): string {
  const summary = summarize(findings);
  const lines = [
    "## VibeGuard Security Summary",
    "",
    `- Findings: ${summary.findings}`,
    `- Blocking: ${summary.blocking}`,
    ""
  ];

  if (findings.length === 0) {
    lines.push("No findings in changed lines.", "");
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

export function renderSarif(findings: Finding[]): string {
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

export function renderFindings(findings: Finding[], format = "table"): string {
  if (format === "json") return renderJson(findings);
  if (format === "sarif") return renderSarif(findings);
  if (format === "markdown") return renderMarkdown(findings);
  return renderTable(findings);
}

function summarize(findings: Finding[]) {
  return {
    findings: findings.length,
    blocking: findings.filter((finding) => finding.blocking).length,
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

