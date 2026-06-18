import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";

test("AI inventory benchmark corpus is versioned", () => {
  const corpus = JSON.parse(readFileSync("benchmarks/ai-inventory-corpus.json", "utf8"));

  assert.equal(corpus.schemaVersion, "vibeguard.aibomBenchmark.v1");
  assert.equal(corpus.cases.length >= 6, true);
});

test("AI inventory benchmark passes", () => {
  const result = spawnSync("node", ["scripts/benchmark-aibom.mjs"], { encoding: "utf8" });

  assert.equal(result.status, 0, result.stderr || result.stdout);
  const output = JSON.parse(result.stdout);
  assert.equal(output.passing, output.cases);
});
