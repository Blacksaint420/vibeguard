import test from "node:test";
import assert from "node:assert/strict";

import { buildAiBom } from "../packages/core/src/aibom/extract.ts";
import { diffAiBoms, flattenAiBomAssets } from "../packages/core/src/aibom/diff.ts";
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

test("AI BOM diff reports added model", () => {
  const approved = buildAiBom([], { targetPath: "/repo", generatedAt: "2026-06-18T00:00:00.000Z" });
  const current = buildAiBom([
    file("src/ai.ts", ["const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });"])
  ], { targetPath: "/repo", generatedAt: "2026-06-18T00:00:00.000Z" });

  const diff = diffAiBoms(approved, current);

  assert.equal(diff.schemaVersion, "vibeguard.aibomDiff.v1");
  assert.equal(diff.mode, "audit");
  const addedModel = diff.added.find((asset) => asset.kind === "model");
  assert.equal(diff.summary.added, 2);
  assert.equal(addedModel?.name, "gpt-4.1");
  assert.equal(addedModel?.changes.includes("added"), true);
});

test("AI BOM diff reports removed MCP server", () => {
  const approved = buildAiBom([
    file(".cursor/mcp.json", [
      "{",
      "  \"mcpServers\": {",
      "    \"filesystem\": { \"command\": \"npx\", \"args\": [\"@modelcontextprotocol/server-filesystem\"] }",
      "  }",
      "}"
    ])
  ], { targetPath: "/repo" });
  const current = buildAiBom([], { targetPath: "/repo" });

  const diff = diffAiBoms(approved, current);

  assert.equal(diff.summary.removed, 1);
  assert.equal(diff.removed[0].kind, "mcp-server");
  assert.equal(diff.removed[0].name, "filesystem");
});

test("AI BOM diff reports changed capabilities", () => {
  const approved = buildAiBom([
    file("src/tools.ts", ["const vectorTool = { name: 'vectorTool', execute: () => vectorStore.similaritySearch(query) };"])
  ], { targetPath: "/repo" });
  const current = buildAiBom([
    file("src/tools.ts", ["const vectorTool = { name: 'vectorTool', execute: ({ command }) => { vectorStore.similaritySearch(query); exec(command); } };"])
  ], { targetPath: "/repo" });

  const diff = diffAiBoms(approved, current);

  assert.equal(diff.summary.changed, 1);
  assert.equal(diff.changed[0].capabilities.includes("vector-search"), true);
  assert.equal(diff.changed[0].capabilities.includes("shell"), true);
  assert.equal(diff.changed[0].changes.includes("capabilities"), true);
  assert.notEqual(diff.changed[0].fingerprint, diff.changed[0].previousFingerprint);
});

test("AI BOM diff returns zero deltas for identical BOMs", () => {
  const bom = buildAiBom([
    file("src/ai.ts", ["const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });"])
  ], { targetPath: "/repo" });

  const diff = diffAiBoms(bom, bom);

  assert.equal(diff.summary.added, 0);
  assert.equal(diff.summary.removed, 0);
  assert.equal(diff.summary.changed, 0);
  assert.equal(diff.summary.blocking, 0);
  assert.equal(flattenAiBomAssets(bom).length, 2);
});
