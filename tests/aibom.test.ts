import test from "node:test";
import assert from "node:assert/strict";

import { buildAiBom } from "../packages/core/src/aibom/extract.ts";
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

test("AI BOM extracts providers, models, prompts, tools, agents, vector stores, and MCP servers", () => {
  const bom = buildAiBom([
    file("src/agent.ts", [
      "import OpenAI from 'openai';",
      "const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });",
      "const systemPrompt = 'You are a support agent';",
      "const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });",
      "export const agent = createAgent({ name: 'support-agent', tools: [shellTool, searchTool] });",
      "const shellTool = { name: 'run_shell', execute: ({ command }) => exec(command) };",
      "await vectorStore.similaritySearch(query, 5);"
    ]),
    file(".cursor/mcp.json", [
      "{",
      "  \"mcpServers\": {",
      "    \"filesystem\": { \"command\": \"npx\", \"args\": [\"-y\", \"@modelcontextprotocol/server-filesystem\"] }",
      "  }",
      "}"
    ])
  ], { targetPath: "/repo" });

  assert.equal(bom.schemaVersion, "vibeguard.aibom.v1");
  assert.equal(bom.summary.providers, 1);
  assert.equal(bom.summary.models, 1);
  assert.equal(bom.summary.prompts, 1);
  assert.equal(bom.summary.agents, 1);
  assert.equal(bom.summary.tools, 2);
  assert.equal(bom.summary.vectorStores, 1);
  assert.equal(bom.summary.mcpServers, 1);
  assert.equal(bom.providers[0].name, "openai");
  assert.equal(bom.models[0].name, "gpt-4.1");
  assert.equal(bom.tools.some((tool) => tool.capabilities.includes("shell")), true);
  assert.equal(bom.mcpServers[0].name, "filesystem");
});

test("AI BOM ignores comments and string-only examples", () => {
  const bom = buildAiBom([
    file("src/readme-example.ts", [
      "// const openai = new OpenAI()",
      "const doc = \"openai.chat.completions.create({ model: 'gpt-4.1' })\";"
    ])
  ], { targetPath: "/repo" });

  assert.equal(bom.summary.providers, 0);
  assert.equal(bom.summary.models, 0);
  assert.equal(bom.summary.tools, 0);
});
