import test from "node:test";
import assert from "node:assert/strict";

import { buildAiBom } from "../packages/core/src/aibom/extract.ts";
import { buildAgentCapabilityGraph } from "../packages/core/src/aibom/graph.ts";
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
  assert.equal(graph.risks[0].ruleId, "agent-capability-shell-without-approval");
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
