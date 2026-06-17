#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { buildAiBom, buildAgentCapabilityGraph } from "../packages/core/src/aibom/index.ts";

const corpus = JSON.parse(readFileSync(new URL("../benchmarks/ai-inventory-corpus.json", import.meta.url), "utf8"));
const results = [];

for (const testCase of corpus.cases) {
  const file = {
    path: testCase.file,
    oldPath: testCase.file,
    status: "modified",
    addedLines: testCase.content.map((content, index) => ({ line: index + 1, content })),
    removedLines: [],
    allLines: testCase.content.map((content, index) => ({ line: index + 1, content }))
  };
  const bom = buildAiBom([file], { targetPath: "/benchmark", generatedAt: "2026-06-17T00:00:00.000Z" });
  const graph = buildAgentCapabilityGraph(bom);
  const actual = {
    models: bom.summary.models,
    agents: bom.summary.agents,
    tools: bom.summary.tools,
    highRiskPaths: graph.summary.highRiskPaths
  };
  results.push({
    id: testCase.id,
    expected: testCase.expected,
    actual,
    pass: JSON.stringify(testCase.expected) === JSON.stringify(actual)
  });
}

const summary = {
  schemaVersion: corpus.schemaVersion,
  cases: results.length,
  passing: results.filter((result) => result.pass).length,
  results
};

console.log(JSON.stringify(summary, null, 2));
if (summary.passing !== summary.cases) process.exitCode = 1;
