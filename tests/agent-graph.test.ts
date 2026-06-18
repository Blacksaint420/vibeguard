import test from "node:test";
import assert from "node:assert/strict";

import { buildAiBom } from "../packages/core/src/aibom/extract.ts";
import { buildAgentCapabilityGraph } from "../packages/core/src/aibom/graph.ts";
import { renderAgentGraphMarkdown } from "../packages/output/src/formatters.ts";
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

test("agent capability graph links agents to tools and high-risk capabilities", () => {
  const bom = buildAiBom([
    file("src/agent.ts", [
      "const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });",
      "export const agent = createAgent({ name: 'support-agent', tools: [shellTool, searchTool] });",
      "const shellTool = { name: 'run_shell', execute: ({ command }) => exec(command) };",
      "const searchTool = { name: 'search_docs', execute: ({ query }) => vectorStore.similaritySearch(query, 5) };"
    ])
  ], { targetPath: "/repo", generatedAt: "2026-06-17T00:00:00.000Z" });

  const graph = buildAgentCapabilityGraph(bom);

  assert.equal(graph.schemaVersion, "vibeguard.agentGraph.v1");
  assert.equal(graph.summary.agents, 1);
  assert.equal(graph.summary.highRiskPaths, 1);
  assert.equal(graph.nodes.some((node) => node.kind === "agent" && node.label === "support-agent"), true);
  assert.equal(graph.edges.some((edge) => edge.capability === "shell"), true);
  assert.equal(graph.edges.find((edge) => edge.capability === "shell")?.evidenceStrength, "same-file");
  assert.equal(graph.risks[0].ruleId, "agent-capability-shell-without-approval");
  assert.equal(graph.risks[0].evidenceStrength, "same-file");
});

test("agent capability graph produces no high-risk path for read-only vector search", () => {
  const bom = buildAiBom([
    file("src/search.ts", [
      "const searchTool = { name: 'search_docs', execute: ({ query }) => vectorStore.similaritySearch(query, 5) };"
    ])
  ], { targetPath: "/repo", generatedAt: "2026-06-17T00:00:00.000Z" });

  const graph = buildAgentCapabilityGraph(bom);

  assert.equal(graph.summary.highRiskPaths, 0);
  assert.equal(graph.risks.length, 0);
});

test("agent capability graph labels direct, same-file, and repository-inferred evidence", () => {
  const bom = buildAiBom([
    file("src/agent.ts", [
      "export const agent = createAgent({ name: 'support-agent', tools: [shellTool] });",
      "const shellTool = { name: 'run_shell', execute: ({ command }) => exec(command) };"
    ]),
    file("src/model.ts", [
      "const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });"
    ])
  ], { targetPath: "/repo", generatedAt: "2026-06-17T00:00:00.000Z" });

  const graph = buildAgentCapabilityGraph(bom);
  const agent = bom.agents[0];
  const model = bom.models[0];
  const shellTool = bom.tools.find((tool) => tool.name === "shellTool");

  assert.equal(graph.edges.find((edge) => edge.from === shellTool?.id && edge.capability === "shell")?.evidenceStrength, "direct");
  assert.equal(graph.edges.find((edge) => edge.from === agent.id && edge.to === shellTool?.id)?.evidenceStrength, "same-file");
  assert.equal(graph.edges.find((edge) => edge.from === agent.id && edge.to === model.id)?.evidenceStrength, "repository-inferred");
  assert.equal(graph.risks.find((risk) => risk.assetId === shellTool?.id)?.evidenceStrength, "same-file");
});

test("agent graph markdown labels inferred high-risk paths", () => {
  const bom = buildAiBom([
    file("src/agent.ts", [
      "export const agent = createAgent({ name: 'support-agent' });"
    ]),
    file("src/tools.ts", [
      "const shellTool = { name: 'run_shell', execute: ({ command }) => exec(command) };"
    ])
  ], { targetPath: "/repo", generatedAt: "2026-06-17T00:00:00.000Z" });

  const graph = buildAgentCapabilityGraph(bom);
  const markdown = renderAgentGraphMarkdown(graph);

  assert.equal(graph.risks[0].evidenceStrength, "repository-inferred");
  assert.equal(markdown.includes("evidence=repository-inferred"), true);
});
