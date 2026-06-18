import test from "node:test";
import assert from "node:assert/strict";

import { buildAiBom } from "../packages/core/src/aibom/extract.ts";
import { evaluateAiBomPolicy } from "../packages/core/src/aibom/policy.ts";
import { defaultAiGovernancePolicy, loadPolicyFromText } from "../packages/core/src/policy.ts";
import type { DiffFile } from "../packages/core/src/types.ts";

function file(path: string, lines: string[]): DiffFile {
  return {
    path,
    oldPath: path,
    status: "modified",
    addedLines: lines.map((content, index) => ({ line: index + 1, content })),
    removedLines: [],
    allLines: lines.map((content, index) => ({ line: index + 1, content }))
  };
}

test("default AI governance policy is audit-only", () => {
  const policy = defaultAiGovernancePolicy();

  assert.equal(policy.mode, "audit");
  assert.equal(policy.blockOnDrift, false);
  assert.deepEqual(policy.blockedCapabilities, []);
  assert.equal(policy.changeRisk.mode, "audit");
  assert.deepEqual(policy.changeRisk.blockSeverities, ["critical"]);
});

test("loadPolicyFromText parses AI governance YAML section", () => {
  const policy = loadPolicyFromText([
    "mode: warn",
    "aiGovernance:",
    "  mode: block",
    "  approvedBom: .vibeguard/approved-aibom.json",
    "  blockOnDrift: true",
    "  allowedProviders:",
    "    - openai",
    "  blockedProviders:",
    "    - unknown",
    "  allowedModels:",
    "    - gpt-4.1",
    "  blockedModels:",
    "    - '*-preview'",
    "  allowedMcpServers:",
    "    - filesystem-readonly",
    "  blockedCapabilities:",
    "    - shell",
    "  allowedCapabilities:",
    "    - llm-call",
    "    - external-provider",
    "  assetAllowlist:",
    "    - kind: model",
    "      name: gpt-4.1",
    "      capabilities: llm-call",
    "  exceptions:",
    "    - assetId: model:openai:gpt-4.1-preview",
    "      reason: Limited evaluation",
    "      reviewer: security@example.com",
    "      expires: 2099-09-30",
    "  changeRisk:",
    "    mode: block",
    "    blockSeverities:",
    "      - critical",
    "      - high",
    "    blockEvents:",
    "      - added-shell-capable-agent"
  ].join("\n"));

  assert.equal(policy.mode, "warn");
  assert.equal(policy.aiGovernance.mode, "block");
  assert.equal(policy.aiGovernance.approvedBom, ".vibeguard/approved-aibom.json");
  assert.equal(policy.aiGovernance.blockOnDrift, true);
  assert.deepEqual(policy.aiGovernance.allowedProviders, ["openai"]);
  assert.deepEqual(policy.aiGovernance.blockedProviders, ["unknown"]);
  assert.deepEqual(policy.aiGovernance.allowedModels, ["gpt-4.1"]);
  assert.deepEqual(policy.aiGovernance.blockedModels, ["*-preview"]);
  assert.deepEqual(policy.aiGovernance.allowedMcpServers, ["filesystem-readonly"]);
  assert.deepEqual(policy.aiGovernance.blockedCapabilities, ["shell"]);
  assert.deepEqual(policy.aiGovernance.allowedCapabilities, ["llm-call", "external-provider"]);
  assert.deepEqual(policy.aiGovernance.assetAllowlist, [{ kind: "model", name: "gpt-4.1", capabilities: ["llm-call"] }]);
  assert.deepEqual(policy.aiGovernance.exceptions, [{
    assetId: "model:openai:gpt-4.1-preview",
    reason: "Limited evaluation",
    reviewer: "security@example.com",
    expires: "2099-09-30"
  }]);
  assert.equal(policy.aiGovernance.changeRisk.mode, "block");
  assert.deepEqual(policy.aiGovernance.changeRisk.blockSeverities, ["critical", "high"]);
  assert.deepEqual(policy.aiGovernance.changeRisk.blockEvents, ["added-shell-capable-agent"]);
});

test("loadPolicyFromText parses AI governance JSON policy", () => {
  const policy = loadPolicyFromText(JSON.stringify({
    mode: "warn",
    aiGovernance: {
      mode: "block",
      blockOnDrift: true,
      allowedProviders: ["openai"],
      blockedCapabilities: ["shell"],
      changeRisk: {
        mode: "block",
        blockSeverities: ["critical", "high"],
        blockEvents: ["added-dangerous-mcp-server"]
      }
    }
  }));

  assert.equal(policy.mode, "warn");
  assert.equal(policy.aiGovernance.mode, "block");
  assert.equal(policy.aiGovernance.blockOnDrift, true);
  assert.deepEqual(policy.aiGovernance.allowedProviders, ["openai"]);
  assert.deepEqual(policy.aiGovernance.blockedCapabilities, ["shell"]);
  assert.equal(policy.aiGovernance.changeRisk.mode, "block");
  assert.deepEqual(policy.aiGovernance.changeRisk.blockSeverities, ["critical", "high"]);
  assert.deepEqual(policy.aiGovernance.changeRisk.blockEvents, ["added-dangerous-mcp-server"]);
});

test("AI BOM policy evaluator reports audit-only unauthorized providers by default", () => {
  const currentBom = buildAiBom([
    file("src/ai.ts", ["const anthropic = new Anthropic();"])
  ], { targetPath: "/repo" });
  const policy = {
    ...defaultAiGovernancePolicy(),
    allowedProviders: ["openai"]
  };

  const result = evaluateAiBomPolicy({ currentBom, policy, generatedAt: "2026-06-18T00:00:00.000Z" });

  assert.equal(result.summary.unauthorized, 1);
  assert.equal(result.summary.blocking, 0);
  assert.equal(result.violations[0].blocking, false);
  assert.equal(result.violations[0].driftType, "unauthorized");
});

test("AI BOM policy evaluator blocks configured unauthorized assets in block mode", () => {
  const currentBom = buildAiBom([
    file("src/ai.ts", ["const anthropic = new Anthropic();"])
  ], { targetPath: "/repo" });
  const policy = {
    ...defaultAiGovernancePolicy(),
    mode: "block" as const,
    allowedProviders: ["openai"]
  };

  const result = evaluateAiBomPolicy({ currentBom, policy });

  assert.equal(result.summary.unauthorized, 1);
  assert.equal(result.summary.blocking, 1);
  assert.equal(result.mode, "block");
  assert.equal(result.violations[0].blocking, true);
});

test("AI BOM policy evaluator blocks configured unauthorized models in block mode", () => {
  const currentBom = buildAiBom([
    file("src/ai.ts", ["const response = await openai.chat.completions.create({ model: 'gpt-4.1-preview', messages });"])
  ], { targetPath: "/repo" });
  const policy = {
    ...defaultAiGovernancePolicy(),
    mode: "block" as const,
    allowedModels: ["gpt-4.1"]
  };

  const result = evaluateAiBomPolicy({ currentBom, policy });

  assert.equal(result.summary.unauthorized, 1);
  assert.equal(result.summary.blocking, 1);
  assert.equal(result.violations[0].blocking, true);
});

test("AI BOM policy evaluator enforces allowed capabilities", () => {
  const currentBom = buildAiBom([
    file("src/ai.ts", ["const openai = new OpenAI();"])
  ], { targetPath: "/repo" });
  const policy = {
    ...defaultAiGovernancePolicy(),
    mode: "block" as const,
    allowedCapabilities: ["llm-call"]
  };

  const result = evaluateAiBomPolicy({ currentBom, policy });

  assert.equal(result.summary.unauthorized, 1);
  assert.equal(result.summary.blocking, 1);
  assert.equal(result.violations[0].ruleId, "aibom-policy/capability-not-allowed");
  assert.equal(result.violations[0].capability, "external-provider");
});

test("AI BOM policy evaluator blocks ordinary asset drift when blockOnDrift is enabled", () => {
  const approvedBom = buildAiBom([], { targetPath: "/repo" });
  const currentBom = buildAiBom([
    file("src/ai.ts", ["const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });"])
  ], { targetPath: "/repo" });
  const policy = {
    ...defaultAiGovernancePolicy(),
    mode: "block" as const,
    blockOnDrift: true
  };

  const result = evaluateAiBomPolicy({ currentBom, approvedBom, policy });

  assert.equal(result.summary.added, 2);
  assert.equal(result.summary.blocking, 2);
  assert.equal(result.violations.some((violation) => violation.driftType === "added" && violation.blocking), true);
});

test("AI BOM policy evaluator honors configured governance blocking severities", () => {
  const currentBom = buildAiBom([
    file("src/tools.ts", ["const fetchTool = { name: 'fetchTool', execute: () => fetch(url) };"])
  ], { targetPath: "/repo" });
  const auditOnlyHighPolicy = {
    ...defaultAiGovernancePolicy(),
    mode: "block" as const,
    blockedCapabilities: ["network"]
  };

  const nonBlockingResult = evaluateAiBomPolicy({ currentBom, policy: auditOnlyHighPolicy });
  assert.equal(nonBlockingResult.summary.blockedCapabilities, 1);
  assert.equal(nonBlockingResult.summary.blocking, 0);

  const blockingHighPolicy = {
    ...auditOnlyHighPolicy,
    changeRisk: {
      ...auditOnlyHighPolicy.changeRisk,
      blockSeverities: ["critical", "high"] as const
    }
  };

  const blockingResult = evaluateAiBomPolicy({ currentBom, policy: blockingHighPolicy });
  assert.equal(blockingResult.summary.blockedCapabilities, 1);
  assert.equal(blockingResult.summary.blocking, 1);
});

test("AI BOM policy evaluator does not honor expired exceptions", () => {
  const currentBom = buildAiBom([
    file("src/ai.ts", ["const response = await openai.chat.completions.create({ model: 'gpt-4.1-preview', messages });"])
  ], { targetPath: "/repo" });
  const model = currentBom.models[0];
  const policy = {
    ...defaultAiGovernancePolicy(),
    mode: "block" as const,
    blockedModels: ["*-preview"],
    exceptions: [{
      assetId: model.id,
      reason: "Old evaluation",
      reviewer: "security@example.com",
      expires: "2020-01-01"
    }]
  };

  const result = evaluateAiBomPolicy({ currentBom, policy });

  assert.equal(result.summary.unauthorized, 1);
  assert.equal(result.summary.blocking, 1);
});

test("AI BOM policy evaluator blocks high-risk capability drift only when enabled", () => {
  const approvedBom = buildAiBom([
    file("src/tools.ts", ["const deployTool = { name: 'deployTool', execute: () => fetch(url) };"])
  ], { targetPath: "/repo" });
  const currentBom = buildAiBom([
    file("src/tools.ts", ["const deployTool = { name: 'deployTool', execute: ({ command }) => exec(command) };"])
  ], { targetPath: "/repo" });
  const policy = {
    ...defaultAiGovernancePolicy(),
    mode: "block" as const,
    blockOnDrift: true
  };

  const result = evaluateAiBomPolicy({ currentBom, approvedBom, policy });

  assert.equal(result.summary.changed, 1);
  assert.equal(result.summary.blockedCapabilities, 1);
  assert.equal(result.summary.blocking, 1);
  assert.equal(result.violations[0].driftType, "blocked-capability");
  assert.equal(result.violations[0].capability, "shell");
});
