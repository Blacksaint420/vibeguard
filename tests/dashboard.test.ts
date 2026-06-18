import test from "node:test";
import assert from "node:assert/strict";

import { buildDashboardData } from "../packages/core/src/dashboard.ts";
import { renderDashboardHtml } from "../packages/output/src/dashboard.ts";

test("buildDashboardData summarizes AI BOM assets", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    aiBom: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.aibom.v1",
      generatedAt: "2026-06-18T00:00:00.000Z",
      targetPath: "/repo",
      summary: {
        providers: 1,
        models: 1,
        prompts: 0,
        agents: 1,
        tools: 1,
        vectorStores: 0,
        mcpServers: 1,
        dataStores: 0,
        highRiskCapabilities: ["shell", "filesystem"]
      },
      providers: [],
      models: [],
      prompts: [],
      agents: [],
      tools: [],
      vectorStores: [],
      mcpServers: [],
      dataStores: []
    }
  });

  assert.equal(dashboard.tool, "vibeguard");
  assert.equal(dashboard.schemaVersion, "vibeguard.dashboard.v1");
  assert.equal(dashboard.summary.posture, "unknown");
  assert.equal(dashboard.summary.aiAssets, 5);
  assert.equal(dashboard.summary.targetPath, "/repo");
  assert.deepEqual(dashboard.summary.highRiskCapabilities, ["shell", "filesystem"]);
  assert.equal(dashboard.dataHandling.localFirst, true);
  assert.equal(dashboard.dataHandling.uploadsByDefault, false);
  assert.equal(dashboard.dataHandling.externalResources, false);
});

test("buildDashboardData records missing optional sections as warnings", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    riskReport: {
      tool: "vibeguard",
      summary: { findings: 2, blocking: 0 },
      coverage: { coverageStatus: "complete", coveragePercent: 100 }
    }
  });

  assert.equal(dashboard.summary.findings, 2);
  assert.equal(dashboard.summary.blocking, 0);
  assert.equal(dashboard.summary.posture, "review");
  assert.equal(dashboard.summary.coverage?.coverageStatus, "complete");
  assert.equal(dashboard.warnings.some((warning) => warning.includes("AI BOM")), true);
});

test("buildDashboardData summarizes governance and change risk artifacts", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    aiBomDiff: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.aibomDiff.v1",
      generatedAt: "2026-06-18T00:00:00.000Z",
      mode: "block",
      currentBom: {
        generatedAt: "2026-06-18T00:00:00.000Z",
        targetPath: "/repo"
      },
      summary: {
        added: 1,
        removed: 0,
        changed: 1,
        unauthorized: 1,
        blockedCapabilities: 1,
        blocking: 2
      },
      added: [],
      removed: [],
      changed: [],
      violations: [
        {
          id: "aibom-policy/provider-not-allowed:test",
          ruleId: "aibom-policy/provider-not-allowed",
          title: "Provider is not approved",
          severity: "high",
          assetId: "provider:unknown",
          assetKind: "provider",
          assetName: "unknown",
          file: "src/ai.ts",
          line: 1,
          reason: "Provider is not in the AI governance allowedProviders list.",
          driftType: "unauthorized",
          evidenceStrength: "direct",
          evidenceSource: "provider syntax",
          blocking: true
        }
      ]
    },
    changeRisk: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.changeRisk.v1",
      summary: { events: 3, blocking: 1 },
      events: [{ id: "event-1" }]
    }
  });

  assert.equal(dashboard.summary.blocking, 3);
  assert.equal(dashboard.summary.governanceViolations, 1);
  assert.equal(dashboard.summary.changeRiskEvents, 3);
  assert.equal(dashboard.summary.posture, "blocked");
});

test("buildDashboardData does not double count governance blocking embedded in risk reports", () => {
  const governance = {
    tool: "vibeguard",
    schemaVersion: "vibeguard.aibomDiff.v1",
    generatedAt: "2026-06-18T00:00:00.000Z",
    mode: "block",
    currentBom: {
      generatedAt: "2026-06-18T00:00:00.000Z",
      targetPath: "/repo"
    },
    summary: {
      added: 0,
      removed: 0,
      changed: 0,
      unauthorized: 1,
      blockedCapabilities: 0,
      blocking: 1
    },
    added: [],
    removed: [],
    changed: [],
    violations: [{
      id: "aibom-policy/provider-not-allowed:test",
      ruleId: "aibom-policy/provider-not-allowed",
      title: "Provider is not approved",
      severity: "high",
      assetId: "provider:unknown",
      assetKind: "provider",
      assetName: "unknown",
      file: "src/ai.ts",
      line: 1,
      reason: "Provider is not in the AI governance allowedProviders list.",
      driftType: "unauthorized",
      evidenceStrength: "direct",
      evidenceSource: "provider syntax",
      blocking: true
    }]
  };

  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    riskReport: {
      tool: "vibeguard",
      summary: { findings: 0, blocking: 1 },
      aiGovernance: governance
    },
    aiBomDiff: governance
  });

  assert.equal(dashboard.summary.blocking, 1);
  assert.equal(dashboard.summary.governanceViolations, 1);
});

test("buildDashboardData keeps standalone governance and change-risk activity out of pass posture", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    riskReport: {
      tool: "vibeguard",
      summary: { findings: 0, blocking: 0 },
      derivedSummary: { overallPosture: "pass" }
    },
    aiBomDiff: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.aibomDiff.v1",
      generatedAt: "2026-06-18T00:00:00.000Z",
      mode: "audit",
      currentBom: {
        generatedAt: "2026-06-18T00:00:00.000Z",
        targetPath: "/repo"
      },
      summary: {
        added: 0,
        removed: 0,
        changed: 0,
        unauthorized: 1,
        blockedCapabilities: 0,
        blocking: 0
      },
      added: [],
      removed: [],
      changed: [],
      violations: [{
        id: "aibom-policy/provider-not-allowed:test",
        ruleId: "aibom-policy/provider-not-allowed",
        title: "Provider is not approved",
        severity: "high",
        assetId: "provider:unknown",
        assetKind: "provider",
        assetName: "unknown",
        file: "src/ai.ts",
        line: 1,
        reason: "Provider is not in the AI governance allowedProviders list.",
        driftType: "unauthorized",
        evidenceStrength: "direct",
        evidenceSource: "provider syntax",
        blocking: false
      }]
    }
  });

  assert.equal(dashboard.summary.posture, "review");
});

test("buildDashboardData tolerates partial AI BOM diff artifacts", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    aiBomDiff: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.aibomDiff.v1",
      generatedAt: "2026-06-18T00:00:00.000Z",
      summary: { blocking: 1 }
    }
  });

  assert.equal(dashboard.aiBomDiff?.violations.length, 0);
  assert.equal(dashboard.summary.blocking, 1);
  assert.equal(dashboard.summary.governanceViolations, 0);
  assert.equal(dashboard.summary.posture, "blocked");
});

test("buildDashboardData clamps malformed negative counts and filters malformed violations", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    riskReport: {
      tool: "vibeguard",
      summary: { findings: 0, blocking: 1 }
    },
    aiBomDiff: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.aibomDiff.v1",
      generatedAt: "2026-06-18T00:00:00.000Z",
      summary: { blocking: -1 },
      violations: [null]
    }
  });

  assert.equal(dashboard.summary.blocking, 1);
  assert.equal(dashboard.summary.governanceViolations, 0);
  assert.equal(dashboard.summary.posture, "blocked");
});

test("buildDashboardData warns for missing artifact refs and optional sections", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    riskReport: {
      tool: "vibeguard",
      summary: { findings: 0, blocking: 0 }
    },
    artifactRefs: [{
      name: "manifest",
      path: ".vibeguard/evidence/latest/manifest.json",
      status: "missing",
      message: "Manifest was not found."
    }]
  });

  assert.equal(dashboard.warnings.includes("Manifest was not found."), true);
  assert.equal(dashboard.warnings.some((warning) => warning.includes("Suppressions artifact is missing")), true);
  assert.equal(dashboard.warnings.some((warning) => warning.includes("GRC mappings artifact is missing")), true);
});

test("buildDashboardData records invalid provided sections and rejects empty input", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    aiBom: { schemaVersion: "not-a-bom" },
    riskReport: { tool: "vibeguard", summary: { findings: 0, blocking: 0 } }
  });

  assert.equal(dashboard.aiBom, undefined);
  assert.equal(dashboard.artifacts.some((artifact) => artifact.name === "aiBom" && artifact.status === "invalid"), true);
  assert.equal(dashboard.warnings.some((warning) => warning.includes("Invalid AI BOM")), true);

  assert.throws(
    () => buildDashboardData({ generatedAt: "2026-06-18T00:00:00.000Z" }),
    /No recognizable VibeGuard artifacts/
  );
});

test("buildDashboardData rejects malformed AI BOM summaries", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    aiBom: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.aibom.v1",
      generatedAt: "2026-06-18T00:00:00.000Z",
      targetPath: "/repo",
      summary: {
        providers: 1,
        highRiskCapabilities: []
      },
      providers: [],
      models: [],
      prompts: [],
      agents: [],
      tools: [],
      vectorStores: [],
      mcpServers: [],
      dataStores: []
    },
    riskReport: { tool: "vibeguard", summary: { findings: 0, blocking: 0 } }
  });

  assert.equal(dashboard.aiBom, undefined);
  assert.equal(dashboard.summary.aiAssets, 0);
  assert.equal(dashboard.artifacts.some((artifact) => artifact.name === "aiBom" && artifact.status === "invalid"), true);
});

test("buildDashboardData rejects non-string high-risk capabilities", () => {
  const dashboard = buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    aiBom: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.aibom.v1",
      generatedAt: "2026-06-18T00:00:00.000Z",
      targetPath: "/repo",
      summary: {
        providers: 0,
        models: 0,
        prompts: 0,
        agents: 0,
        tools: 0,
        vectorStores: 0,
        mcpServers: 0,
        dataStores: 0,
        highRiskCapabilities: ["shell", 7]
      },
      providers: [],
      models: [],
      prompts: [],
      agents: [],
      tools: [],
      vectorStores: [],
      mcpServers: [],
      dataStores: []
    },
    riskReport: { tool: "vibeguard", summary: { findings: 0, blocking: 0 } }
  });

  assert.equal(dashboard.aiBom, undefined);
  assert.deepEqual(dashboard.summary.highRiskCapabilities, []);
  assert.equal(dashboard.artifacts.some((artifact) => artifact.name === "aiBom" && artifact.status === "invalid"), true);
});

test("renderDashboardHtml escapes HTML from artifact values", () => {
  const html = renderDashboardHtml(buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    riskReport: {
      tool: "vibeguard",
      summary: { findings: 1, blocking: 0 },
      findings: [{ title: "<img src=x onerror=alert(1)>", severity: "high", file: "src/ai.ts", line: 1 }]
    }
  }));

  assert.equal(html.includes("<img src=x onerror=alert(1)>"), false);
  assert.equal(html.includes("&lt;img src=x onerror=alert(1)&gt;"), true);
  assert.equal(html.includes("https://"), false);
});

test("renderDashboardHtml is self contained", () => {
  const html = renderDashboardHtml(buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    riskReport: { tool: "vibeguard", summary: { findings: 0, blocking: 0 } }
  }));

  assert.equal(/<script\s+src=/i.test(html), false);
  assert.equal(/<link\s+[^>]*href=/i.test(html), false);
  assert.equal(/cdn\.|googleapis|analytics/i.test(html), false);
  assert.equal(html.includes("uploadsByDefault"), true);
  assert.equal(html.includes("default-src 'none'"), true);
});

test("renderDashboardHtml includes primary dashboard sections", () => {
  const html = renderDashboardHtml(buildDashboardData({
    generatedAt: "2026-06-18T00:00:00.000Z",
    riskReport: { tool: "vibeguard", summary: { findings: 0, blocking: 0 } },
    agentGraph: {
      tool: "vibeguard",
      schemaVersion: "vibeguard.agentGraph.v1",
      generatedAt: "2026-06-18T00:00:00.000Z",
      targetPath: "/repo",
      summary: { agents: 1, tools: 1, capabilities: 1, highRiskPaths: 1 },
      nodes: [
        { id: "agent:deploy", kind: "agent", label: "deploy" },
        { id: "tool:shell", kind: "tool", label: "shellTool" },
        { id: "capability:shell", kind: "capability", label: "shell" }
      ],
      edges: [
        { from: "agent:deploy", to: "tool:shell", relation: "uses", capability: "shell", evidenceStrength: "direct", evidenceSource: "test", detectionMethod: "test" },
        { from: "tool:shell", to: "capability:shell", relation: "exposes", capability: "shell", evidenceStrength: "direct", evidenceSource: "test", detectionMethod: "test" }
      ],
      risks: [{
        ruleId: "agent-capability-shell-without-approval",
        title: "Agent can reach shell execution",
        severity: "critical",
        assetId: "tool:shell",
        capability: "shell",
        path: ["agent:deploy", "tool:shell", "capability:shell"],
        evidenceStrength: "direct",
        evidenceSource: "test",
        detectionMethod: "test",
        evidence: "shellTool exposes shell capability.",
        suggestedFix: "Require approval."
      }]
    }
  }));

  for (const label of ["Overview", "AI BOM Inventory", "Approved BOM Status", "Agent Capability Graph", "AI Change-Risk", "AI-Aware SAST Findings", "Enterprise/GRC", "Coverage"]) {
    assert.equal(html.includes(label), true, `${label} should render`);
  }
  assert.equal(html.includes("<svg"), true);
  assert.equal(html.includes("Graph edge fallback"), true);
});
