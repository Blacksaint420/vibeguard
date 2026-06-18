import type { AgentCapabilityGraph, AgentGraphEdge, AgentGraphNode, AiAsset, AiBom } from "../../core/src/aibom/index.ts";
import type { DashboardData } from "../../core/src/dashboard.ts";

type AnyRecord = Record<string, unknown>;

const SECTION_TABS = [
  ["overview", "Overview"],
  ["aibom", "AI BOM Inventory"],
  ["governance", "Approved BOM Status"],
  ["graph", "Agent Capability Graph"],
  ["change-risk", "AI Change-Risk"],
  ["sast", "AI-Aware SAST Findings"],
  ["grc", "Enterprise/GRC"],
  ["coverage", "Coverage"]
] as const;

const HIGH_RISK_CAPABILITIES = new Set(["shell", "filesystem", "database", "network", "secret-access", "mcp-tool"]);

export function renderDashboardHtml(data: DashboardData): string {
  const json = escapeJsonForHtml(data);
  return [
    "<!doctype html>",
    '<html lang="en">',
    "<head>",
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; img-src data:; style-src \'unsafe-inline\'; script-src \'unsafe-inline\';">',
    `<title>${escapeHtml(dashboardTitle(data))}</title>`,
    `<style>${dashboardCss()}</style>`,
    "</head>",
    "<body>",
    '<a class="skip-link" href="#main">Skip to dashboard content</a>',
    renderShell(data),
    `<script id="vibeguard-dashboard-data" type="application/json">${json}</script>`,
    `<script>${dashboardJs()}</script>`,
    "</body>",
    "</html>"
  ].join("\n");
}

export function escapeHtml(value: unknown): string {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

export function escapeJsonForHtml(value: unknown): string {
  return JSON.stringify(value)
    .replaceAll("<", "\\u003c")
    .replaceAll(">", "\\u003e")
    .replaceAll("&", "\\u0026")
    .replaceAll("\u2028", "\\u2028")
    .replaceAll("\u2029", "\\u2029");
}

function dashboardTitle(data: DashboardData): string {
  return `VibeGuard Dashboard - ${data.summary.posture.toUpperCase()}`;
}

function renderShell(data: DashboardData): string {
  return [
    '<header class="hero">',
    '<div class="hero-copy">',
    "<p>VibeGuard Local Dashboard</p>",
    `<h1>${escapeHtml(data.summary.posture.toUpperCase())} posture</h1>`,
    `<p>Generated ${escapeHtml(data.generatedAt)}${data.summary.targetPath ? ` for ${escapeHtml(data.summary.targetPath)}` : ""}.</p>`,
    "</div>",
    '<div class="hero-metrics">',
    metric("Blocking", data.summary.blocking),
    metric("Findings", data.summary.findings),
    metric("AI assets", data.summary.aiAssets),
    metric("Governance", data.summary.governanceViolations),
    "</div>",
    "</header>",
    '<nav class="tabs" aria-label="Dashboard sections">',
    SECTION_TABS.map(([id, label], index) => `<button type="button" class="tab${index === 0 ? " active" : ""}" data-tab="${id}" aria-controls="section-${id}">${escapeHtml(label)}</button>`).join(""),
    "</nav>",
    '<main id="main">',
    renderOverview(data),
    renderAiBomSection(data.aiBom),
    renderGovernanceSection(data),
    renderGraphSection(data.agentGraph),
    renderChangeRiskSection(data.changeRisk),
    renderSastSection(data.riskReport),
    renderGrcSection(data),
    renderCoverageSection(data),
    "</main>",
    '<footer class="footer">',
    "Local-first dashboard: all data is read from local artifacts. No source, prompts, findings, exceptions, suppressions, secrets, or telemetry are uploaded by default.",
    "</footer>"
  ].join("\n");
}

function renderOverview(data: DashboardData): string {
  return section("overview", "Overview", [
    '<div class="cards">',
    metric("Posture", data.summary.posture),
    metric("Blocking", data.summary.blocking),
    metric("Findings", data.riskReport ? data.summary.findings : "Unavailable"),
    metric("AI assets", data.aiBom ? data.summary.aiAssets : "Unavailable"),
    metric("Governance violations", data.aiBomDiff ? data.summary.governanceViolations : "Unavailable"),
    metric("Change-risk events", data.changeRisk ? data.summary.changeRiskEvents : "Unavailable"),
    metric("Coverage", data.summary.coverage ? `${data.summary.coverage.coveragePercent}% ${data.summary.coverage.coverageStatus}` : "Unavailable"),
    metric("High-risk capabilities", data.aiBom ? data.summary.highRiskCapabilities.join(", ") || "none" : "Unavailable"),
    "</div>",
    data.artifacts.length > 0
      ? table(
        "Artifacts",
        ["Name", "Status", "Schema", "Path", "SHA-256", "Message"],
        data.artifacts.map((artifact) => [
          artifact.name,
          artifact.status,
          artifact.schemaVersion ?? "",
          artifact.path ?? "",
          artifact.sha256 ?? "",
          artifact.message ?? ""
        ])
      )
      : unavailable("No artifact manifest was supplied. Use --input with an evidence-pack directory or pass explicit artifact flags."),
    data.warnings.length > 0
      ? `<div class="panel warn"><h3>Warnings</h3><ul>${data.warnings.map((warning) => `<li>${escapeHtml(warning)}</li>`).join("")}</ul></div>`
      : '<div class="panel ok">No dashboard artifact warnings.</div>',
    `<pre class="data-handling">${escapeHtml(JSON.stringify(data.dataHandling, null, 2))}</pre>`
  ]);
}

function renderAiBomSection(aiBom: AiBom | undefined): string {
  if (!aiBom) {
    return section("aibom", "AI BOM Inventory", [unavailable("Run: vibeguard aibom . --format aibom-json --output aibom.json")]);
  }
  const assets = flattenAiAssets(aiBom);
  return section("aibom", "AI BOM Inventory", [
    '<div class="toolbar"><label>Search <input id="aibom-search" type="search" placeholder="asset, file, capability"></label><label>Kind <select id="aibom-kind"><option value="">All</option>' +
      [...new Set(assets.map((asset) => asset.kind))].sort().map((kind) => `<option value="${escapeHtml(kind)}">${escapeHtml(kind)}</option>`).join("") +
      '</select></label><label><input id="aibom-high-risk" type="checkbox"> High-risk capability</label></div>',
    table(
      "AI assets",
      ["Kind", "Name", "Location", "Confidence", "Evidence", "Capabilities", "Fingerprint"],
      assets.map((asset) => [
        asset.kind,
        asset.name,
        `${asset.file}:${asset.line}`,
        asset.confidence,
        `${asset.evidenceStrength} - ${asset.evidenceSource}`,
        asset.capabilities.join(", "),
        asset.fingerprint
      ]),
      "aibom-table"
    )
  ]);
}

function renderGovernanceSection(data: DashboardData): string {
  const diff = data.aiBomDiff;
  if (!diff) {
    return section("governance", "Approved BOM Status", [unavailable("Run: vibeguard aibom diff --approved-aibom .vibeguard/approved-aibom.json --format json --output aibom-diff.json")]);
  }
  return section("governance", "Approved BOM Status", [
    '<div class="cards">',
    metric("Mode", diff.mode),
    metric("Added", diff.summary.added),
    metric("Removed", diff.summary.removed),
    metric("Changed", diff.summary.changed),
    metric("Unauthorized", diff.summary.unauthorized),
    metric("Blocking", diff.summary.blocking),
    "</div>",
    diff.violations.length > 0
      ? table(
        "Governance violations",
        ["Status", "Severity", "Type", "Asset", "Location", "Capability", "Reason", "Evidence"],
        diff.violations.map((violation) => [
          violation.blocking ? "BLOCK" : "AUDIT",
          violation.severity,
          violation.driftType,
          `${violation.assetKind}:${violation.assetName}`,
          `${violation.file}:${violation.line}`,
          violation.capability ?? "",
          violation.reason,
          `${violation.evidenceStrength} - ${violation.evidenceSource}`
        ])
      )
      : '<div class="panel ok">No AI BOM governance violations detected.</div>',
    renderGovernanceGroups(diff.violations)
  ]);
}

function renderGraphSection(graph: AgentCapabilityGraph | undefined): string {
  if (!graph) {
    return section("graph", "Agent Capability Graph", [unavailable("Run: vibeguard graph . --format graph-json --output agent-graph.json")]);
  }
  return section("graph", "Agent Capability Graph", [
    '<div class="cards">',
    metric("Agents", graph.summary.agents),
    metric("Tools", graph.summary.tools),
    metric("Capabilities", graph.summary.capabilities),
    metric("High-risk paths", graph.summary.highRiskPaths),
    "</div>",
    renderGraphSvg(graph),
    table(
      "Graph edge fallback",
      ["From", "Relation", "To", "Capability", "Evidence"],
      graph.edges.map((edge) => [
        nodeLabel(graph, edge.from),
        edge.relation,
        nodeLabel(graph, edge.to),
        edge.capability ?? "",
        `${edge.evidenceStrength} - ${edge.evidenceSource}`
      ])
    ),
    graph.risks.length > 0
      ? table(
        "High-risk paths",
        ["Severity", "Capability", "Path", "Evidence", "Suggested fix"],
        graph.risks.map((risk) => [
          risk.severity,
          risk.capability,
          risk.path.map((id) => nodeLabel(graph, id)).join(" -> "),
          `${risk.evidenceStrength} - ${risk.evidence}`,
          risk.suggestedFix
        ])
      )
      : '<div class="panel ok">No high-risk graph paths detected.</div>'
  ]);
}

function renderChangeRiskSection(changeRisk: Record<string, unknown> | undefined): string {
  if (!changeRisk) {
    return section("change-risk", "AI Change-Risk", [unavailable("Run: vibeguard change-risk . --format json --output change-risk.json")]);
  }
  const events = Array.isArray(changeRisk.events) ? changeRisk.events.filter(isRecord) : [];
  return section("change-risk", "AI Change-Risk", [
    events.length > 0
      ? table(
        "Change-risk events",
        ["Severity", "Type", "Title", "Location", "Evidence", "Suggested fix", "Blocking"],
        events.map((event) => [
          text(event.severity),
          text(event.type),
          text(event.title),
          `${text(event.file)}:${text(event.line)}`,
          text(event.evidence),
          text(event.suggestedFix),
          event.blocking === true ? "yes" : "no"
        ])
      )
      : '<div class="panel ok">No AI change-risk events supplied.</div>'
  ]);
}

function renderSastSection(riskReport: DashboardData["riskReport"] | undefined): string {
  if (!isRecord(riskReport)) {
    return section("sast", "AI-Aware SAST Findings", [unavailable("Run: vibeguard check . --format json --output sast.json")]);
  }
  const findings = Array.isArray(riskReport.findings) ? riskReport.findings.filter(isRecord) : [];
  return section("sast", "AI-Aware SAST Findings", [
    '<div class="toolbar"><label>Severity <select id="sast-severity"><option value="">All</option><option>critical</option><option>high</option><option>medium</option><option>low</option></select></label><label>OWASP <input id="sast-owasp" type="search" placeholder="LLM01:2025"></label><label>Evidence <input id="sast-evidence" type="search" placeholder="direct"></label></div>',
    findings.length > 0
      ? table(
        "SAST findings",
        ["Severity", "Confidence", "Rule", "Title", "Location", "Evidence", "Suggested fix", "Test"],
        findings.map((finding) => [
          text(finding.severity),
          text(finding.confidence),
          text(finding.ruleId),
          text(finding.title),
          `${text(finding.file)}:${text(finding.line)}`,
          `${text(finding.evidenceStrength)} - ${text(finding.evidenceSource)}`,
          safePreview(finding.suggestedFix),
          safePreview(finding.testSuggestion)
        ]),
        "sast-table"
      )
      : '<div class="panel ok">No SAST findings supplied at the active policy threshold.</div>'
  ]);
}

function renderGrcSection(data: DashboardData): string {
  const findings = isRecord(data.riskReport) && Array.isArray(data.riskReport.findings) ? data.riskReport.findings.filter(isRecord) : [];
  const suppressions = data.suppressions ?? [];
  const frameworkCounts = countFrameworks(findings);
  return section("grc", "Enterprise/GRC", [
    '<div class="cards">',
    metric("OWASP LLM", frameworkCounts["owasp-llm-2025"] ?? 0),
    metric("NIST AI RMF", frameworkCounts["nist-ai-rmf"] ?? 0),
    metric("MITRE ATLAS", frameworkCounts["mitre-atlas"] ?? 0),
    metric("Google SAIF", frameworkCounts["google-saif"] ?? 0),
    "</div>",
    findings.length > 0
      ? table(
        "Framework mappings",
        ["Rule", "Frameworks", "Risk category", "Control gaps"],
        findings.map((finding) => [
          text(finding.ruleId),
          Array.isArray(finding.frameworks) ? finding.frameworks.filter(isRecord).map((mapping) => `${text(mapping.framework)} ${text(mapping.id)}`).join(", ") : "",
          isRecord(finding.risk) ? text(finding.risk.category) : "",
          Array.isArray(finding.controlGaps) ? finding.controlGaps.map(text).join(", ") : ""
        ])
      )
      : '<div class="panel muted">No framework mappings supplied.</div>',
    suppressions.length > 0
      ? table("Suppressions and exceptions", ["Reviewer", "Reason", "Expires", "Status", "Entry"], suppressions.map((entry) => {
        const record = isRecord(entry) ? entry : {};
        const expires = text(record.expires);
        return [text(record.reviewer), text(record.reason), expires, suppressionStatus(expires), JSON.stringify(entry)];
      }))
      : '<div class="panel muted">No suppressions artifact supplied.</div>',
    data.grcMappings ? `<pre>${escapeHtml(JSON.stringify(data.grcMappings, null, 2))}</pre>` : ""
  ]);
}

function renderCoverageSection(data: DashboardData): string {
  const coverage = data.summary.coverage;
  if (!coverage) {
    return section("coverage", "Coverage", [unavailable("Run: vibeguard check . --format json --output sast.json to include coverage data.")]);
  }
  return section("coverage", "Coverage", [
    table("Coverage summary", ["Metric", "Value"], [
      ["Files discovered", String(coverage.filesDiscovered)],
      ["Files scanned", String(coverage.filesScanned)],
      ["Files skipped", String(coverage.filesSkipped)],
      ["Policy excluded", String(coverage.filesExcludedByPolicy)],
      ["Binary skipped", String(coverage.filesSkippedBinary)],
      ["Oversized skipped", String(coverage.filesSkippedOversized)],
      ["Unreadable", String(coverage.filesUnreadable)],
      ["File limit reached", coverage.fileLimitReached ? "yes" : "no"],
      ["Coverage", `${coverage.coveragePercent}% ${coverage.coverageStatus}`]
    ]),
    data.warnings.length > 0
      ? table("Coverage and artifact warnings", ["Warning"], data.warnings.map((warning) => [warning]))
      : '<div class="panel ok">No coverage or artifact warnings.</div>'
  ]);
}

function renderGraphSvg(graph: AgentCapabilityGraph): string {
  const positions = layoutGraph(graph.nodes);
  const width = 920;
  const height = Math.max(260, Math.max(...[...positions.values()].map((point) => point.y), 180) + 80);
  const edges = graph.edges.map((edge) => {
    const from = positions.get(edge.from);
    const to = positions.get(edge.to);
    if (!from || !to) return "";
    const highRisk = edge.capability ? HIGH_RISK_CAPABILITIES.has(edge.capability) : false;
    return `<g><line x1="${from.x}" y1="${from.y}" x2="${to.x}" y2="${to.y}" class="${highRisk ? "edge high" : "edge"}"/><text x="${(from.x + to.x) / 2}" y="${(from.y + to.y) / 2 - 6}" class="edge-label">${escapeHtml(edge.relation)}${highRisk ? " high risk" : ""}</text></g>`;
  }).join("");
  const nodes = graph.nodes.map((node) => {
    const point = positions.get(node.id);
    if (!point) return "";
    return `<g><rect x="${point.x - 66}" y="${point.y - 22}" width="132" height="44" rx="8" class="node ${escapeHtml(node.kind)}"/><text x="${point.x}" y="${point.y + 4}" text-anchor="middle">${escapeHtml(node.label)}</text></g>`;
  }).join("");
  return `<div class="graph-wrap"><svg role="img" aria-label="Agent capability graph" viewBox="0 0 ${width} ${height}">${edges}${nodes}</svg></div>`;
}

function layoutGraph(nodes: AgentGraphNode[]): Map<string, { x: number; y: number }> {
  const columns: Record<string, number> = {
    agent: 120,
    tool: 340,
    "mcp-server": 340,
    capability: 560,
    "data-store": 780,
    "vector-store": 780
  };
  const buckets = new Map<number, AgentGraphNode[]>();
  for (const node of nodes) {
    const x = columns[node.kind] ?? 340;
    buckets.set(x, [...(buckets.get(x) ?? []), node]);
  }
  const positions = new Map<string, { x: number; y: number }>();
  for (const [x, bucket] of buckets) {
    bucket.forEach((node, index) => positions.set(node.id, { x, y: 70 + index * 72 }));
  }
  return positions;
}

function flattenAiAssets(aiBom: AiBom): AiAsset[] {
  return [
    ...aiBom.providers,
    ...aiBom.models,
    ...aiBom.prompts,
    ...aiBom.agents,
    ...aiBom.tools,
    ...aiBom.mcpServers,
    ...aiBom.vectorStores,
    ...aiBom.dataStores
  ];
}

function section(id: string, title: string, content: string[]): string {
  return `<section id="section-${id}" class="dashboard-section${id === "overview" ? " active" : ""}" data-section="${id}"><h2>${escapeHtml(title)}</h2>${content.join("\n")}</section>`;
}

function metric(label: string, value: unknown): string {
  return `<div class="metric"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`;
}

function table(caption: string, headers: string[], rows: unknown[][], id?: string): string {
  return [
    '<div class="table-wrap">',
    `<table${id ? ` id="${escapeHtml(id)}"` : ""}>`,
    `<caption>${escapeHtml(caption)}</caption>`,
    `<thead><tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr></thead>`,
    `<tbody>${rows.map((row) => `<tr>${row.map((cell) => `<td>${escapeHtml(cell)}</td>`).join("")}</tr>`).join("")}</tbody>`,
    "</table>",
    "</div>"
  ].join("");
}

function renderGovernanceGroups(violations: DashboardData["aiBomDiff"] extends infer T ? T extends { violations: infer V } ? V : never : never): string {
  if (!Array.isArray(violations) || violations.length === 0) return "";
  const counts = new Map<string, number>();
  for (const violation of violations) {
    counts.set(violation.driftType, (counts.get(violation.driftType) ?? 0) + 1);
  }
  return table("Governance groups", ["Group", "Count"], [
    ["Unauthorized asset", counts.get("unauthorized") ?? 0],
    ["Blocked capability", counts.get("blocked-capability") ?? 0],
    ["Added drift", counts.get("added") ?? 0],
    ["Changed drift", counts.get("changed") ?? 0],
    ["Removed asset", counts.get("removed") ?? 0]
  ]);
}

function unavailable(message: string): string {
  return `<div class="panel unavailable"><strong>Unavailable</strong><p>${escapeHtml(message)}</p></div>`;
}

function nodeLabel(graph: AgentCapabilityGraph, id: string): string {
  return graph.nodes.find((node) => node.id === id)?.label ?? id;
}

function text(value: unknown): string {
  return String(value ?? "");
}

function safePreview(value: unknown): string {
  const raw = text(value);
  return raw.length > 220 ? `${raw.slice(0, 217)}...` : raw;
}

function countFrameworks(findings: AnyRecord[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const finding of findings) {
    const frameworks = Array.isArray(finding.frameworks) ? finding.frameworks.filter(isRecord) : [];
    for (const mapping of frameworks) {
      const framework = text(mapping.framework);
      if (framework) counts[framework] = (counts[framework] ?? 0) + 1;
    }
  }
  return counts;
}

function suppressionStatus(expires: string): string {
  if (!expires) return "review-needed";
  const expiresAt = Date.parse(`${expires}T00:00:00.000Z`);
  if (!Number.isFinite(expiresAt)) return "review-needed";
  return expiresAt < Date.now() ? "expired-review-needed" : "active";
}

function isRecord(value: unknown): value is AnyRecord {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function dashboardCss(): string {
  return `
:root{color-scheme:light;--bg:#f6f8fb;--panel:#fff;--ink:#172033;--muted:#647084;--line:#d8dee8;--accent:#174ea6;--danger:#b42318;--warn:#946200;--ok:#287a3e}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;line-height:1.45}
.skip-link{position:absolute;left:-999px;top:8px;background:#fff;padding:8px}.skip-link:focus{left:8px;z-index:3}.hero{display:grid;grid-template-columns:1fr auto;gap:18px;background:#101827;color:#fff;padding:24px}.hero h1{margin:0;font-size:34px}.hero p{margin:0 0 8px}.hero-metrics,.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px}.hero-metrics{min-width:440px}.metric{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:12px;color:var(--ink)}.hero .metric{background:#1e293b;color:#fff;border-color:#334155}.metric span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;font-weight:700}.hero .metric span{color:#cbd5e1}.metric strong{display:block;font-size:24px;overflow-wrap:anywhere}.tabs{position:sticky;top:0;z-index:2;display:flex;gap:6px;overflow-x:auto;background:#eef2f7;border-bottom:1px solid var(--line);padding:8px}.tab{border:1px solid var(--line);background:#fff;border-radius:8px;padding:8px 10px;font-weight:700;white-space:nowrap}.tab.active{background:var(--accent);color:#fff}main{max-width:1280px;margin:0 auto;padding:20px}.dashboard-section{display:none}.dashboard-section.active{display:block}h2{margin:0 0 14px}.panel,.table-wrap,.graph-wrap,pre{background:var(--panel);border:1px solid var(--line);border-radius:8px;padding:14px;margin:12px 0}.warn{border-color:#f3c969}.ok{border-color:#a7d7b3}.unavailable{border-style:dashed}.muted{color:var(--muted)}.toolbar{display:flex;gap:12px;flex-wrap:wrap;margin:8px 0 12px}.toolbar input,.toolbar select{padding:7px;border:1px solid var(--line);border-radius:6px}.table-wrap{overflow-x:auto;padding:0}table{border-collapse:collapse;width:100%;background:#fff}caption{text-align:left;font-weight:800;padding:12px}th,td{border-top:1px solid var(--line);padding:9px;text-align:left;vertical-align:top;overflow-wrap:anywhere}th{background:#f0f3f8;font-size:12px;text-transform:uppercase;color:#435066}svg{width:100%;min-height:260px}.edge{stroke:#94a3b8;stroke-width:2}.edge.high{stroke:var(--danger);stroke-width:4}.edge-label{font-size:11px;fill:#475569}.node{fill:#fff;stroke:#334155;stroke-width:1.5}.node.capability{fill:#fff7ed}.node.agent{fill:#eff6ff}.node.tool,.node.mcp-server{fill:#f0fdf4}.footer{padding:18px;text-align:center;color:var(--muted);border-top:1px solid var(--line);background:#fff}.data-handling{white-space:pre-wrap}
@media(max-width:780px){.hero{grid-template-columns:1fr}.hero-metrics{min-width:0}.hero h1{font-size:26px}main{padding:12px}}
`;
}

function dashboardJs(): string {
  return `
const tabs = document.querySelectorAll('.tab');
const sections = document.querySelectorAll('.dashboard-section');
for (const tab of tabs) {
  tab.addEventListener('click', () => {
    const id = tab.dataset.tab;
    for (const item of tabs) item.classList.toggle('active', item === tab);
    for (const section of sections) section.classList.toggle('active', section.dataset.section === id);
  });
}
function filterTable(table, search, kind) {
  if (!table) return;
  for (const row of table.tBodies[0]?.rows ?? []) {
    const text = row.textContent.toLowerCase();
    const rowKind = row.cells[0]?.textContent.toLowerCase() ?? '';
    row.style.display = (!search || text.includes(search)) && (!kind || rowKind === kind) ? '' : 'none';
  }
}
const aibomSearch = document.getElementById('aibom-search');
const aibomKind = document.getElementById('aibom-kind');
const aibomHighRisk = document.getElementById('aibom-high-risk');
function applyAibomFilter(){
  const table = document.getElementById('aibom-table');
  const search = (aibomSearch?.value ?? '').toLowerCase();
  const kind = (aibomKind?.value ?? '').toLowerCase();
  const highRisk = Boolean(aibomHighRisk?.checked);
  if (!table) return;
  for (const row of table.tBodies[0]?.rows ?? []) {
    const text = row.textContent.toLowerCase();
    const rowKind = row.cells[0]?.textContent.toLowerCase() ?? '';
    const capabilities = row.cells[5]?.textContent.toLowerCase() ?? '';
    const hasHighRisk = ['shell','filesystem','database','network','secret-access','mcp-tool'].some((item) => capabilities.includes(item));
    row.style.display = (!search || text.includes(search)) && (!kind || rowKind === kind) && (!highRisk || hasHighRisk) ? '' : 'none';
  }
}
aibomSearch?.addEventListener('input', applyAibomFilter);
aibomKind?.addEventListener('change', applyAibomFilter);
aibomHighRisk?.addEventListener('change', applyAibomFilter);
const sastSeverity = document.getElementById('sast-severity');
const sastOwasp = document.getElementById('sast-owasp');
const sastEvidence = document.getElementById('sast-evidence');
function applySastFilter(){
  const table = document.getElementById('sast-table');
  if (!table) return;
  const severity = (sastSeverity?.value ?? '').toLowerCase();
  const owasp = (sastOwasp?.value ?? '').toLowerCase();
  const evidence = (sastEvidence?.value ?? '').toLowerCase();
  for (const row of table.tBodies[0]?.rows ?? []) {
    const rowSeverity = row.cells[0]?.textContent.toLowerCase() ?? '';
    const rowText = row.textContent.toLowerCase();
    const rowEvidence = row.cells[5]?.textContent.toLowerCase() ?? '';
    row.style.display = (!severity || rowSeverity === severity) && (!owasp || rowText.includes(owasp)) && (!evidence || rowEvidence.includes(evidence)) ? '' : 'none';
  }
}
sastSeverity?.addEventListener('change', applySastFilter);
sastOwasp?.addEventListener('input', applySastFilter);
sastEvidence?.addEventListener('input', applySastFilter);
`;
}
