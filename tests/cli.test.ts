import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseArgs, runCli } from "../packages/cli/src/cli.ts";

const vulnerableDiff = [
  "diff --git a/src/app.js b/src/app.js",
  "--- a/src/app.js",
  "+++ b/src/app.js",
  "@@ -1,0 +1 @@",
  "+eval(req.body.code);"
].join("\n");

test("parseArgs supports check options", () => {
  const command = parseArgs(["check", "--staged", "--format", "json"]);

  assert.equal(command.name, "check");
  assert.equal(command.staged, true);
  assert.equal(command.format, "json");
});

test("parseArgs supports risk-json output format", () => {
  const command = parseArgs(["check", "--staged", "--format", "risk-json"]);

  assert.equal(command.name, "check");
  assert.equal(command.staged, true);
  assert.equal(command.format, "risk-json");
});

test("parseArgs supports aibom and graph commands", () => {
  const aibom = parseArgs(["aibom", "src", "--format", "aibom-json", "--output", "bom.json"]);
  const graph = parseArgs(["graph", "--format", "graph-json", "--output", "graph.json"]);

  assert.equal(aibom.name, "aibom");
  assert.equal(aibom.targetPath, "src");
  assert.equal(aibom.format, "aibom-json");
  assert.equal(aibom.output, "bom.json");
  assert.equal(graph.name, "graph");
  assert.equal(graph.format, "graph-json");
});

test("parseArgs defaults to the interactive framework", () => {
  const command = parseArgs([]);

  assert.equal(command.name, "interactive");
});

test("parseArgs supports interactive target option", () => {
  const command = parseArgs(["interactive", "--target", "/tmp/CV Maker"]);

  assert.equal(command.name, "interactive");
  assert.equal(command.targetPath, "/tmp/CV Maker");
});

test("parseArgs supports setup guide aliases", () => {
  assert.equal(parseArgs(["setup"]).name, "setup");
  assert.equal(parseArgs(["install"]).name, "setup");
  assert.equal(parseArgs(["configure"]).name, "setup");
});

test("parseArgs supports repository path for full scan", () => {
  const command = parseArgs(["check", "/tmp/CV Maker", "--format", "json"]);

  assert.equal(command.name, "check");
  assert.equal(command.targetPath, "/tmp/CV Maker");
  assert.equal(command.staged, false);
});

test("parseArgs supports enterprise suppress options", () => {
  const command = parseArgs([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-01-01"
  ]);

  assert.equal(command.name, "suppress");
  assert.equal(command.id, "js-eval");
  assert.equal(command.file, "src/app.js");
  assert.equal(command.reason, "accepted for migration");
  assert.equal(command.reviewer, "security@example.com");
  assert.equal(command.expires, "2099-01-01");
});

test("runCli rejects suppressions missing required enterprise fields", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const writes: string[] = [];
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration"
  ], {
    cwd,
    stdout: (text) => writes.push(text),
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(writes.join(""), "");
  assert.equal(errors.join("").includes("Missing required suppression fields: reviewer, expires"), true);
  assert.equal(existsSync(join(cwd, "vibeguard.yml")), false);
});

test("runCli rejects suppressions missing required reason", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-01-01"
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("Missing required suppression fields: reason"), true);
  assert.equal(existsSync(join(cwd, "vibeguard.yml")), false);
});

test("runCli rejects malformed suppression expiration", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-02-30"
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("--expires must be a valid YYYY-MM-DD date"), true);
  assert.equal(existsSync(join(cwd, "vibeguard.yml")), false);
});

test("runCli rejects expired suppression expiration", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2020-01-01"
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("--expires must be a future or current YYYY-MM-DD date"), true);
  assert.equal(existsSync(join(cwd, "vibeguard.yml")), false);
});

test("runCli appends legacy suppressions when config has no suppression policy", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const configPath = join(cwd, "vibeguard.yml");
  writeFileSync(configPath, [
    "mode: block",
    "suppressions: []"
  ].join("\n"));

  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js"
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 0);
  assert.equal(errors.join(""), "");
  assert.equal(readFileSync(configPath, "utf8").includes("  - rule: js-eval"), true);
});

test("runCli returns blocking exit code for vulnerable staged diff", async () => {
  const writes: string[] = [];
  const result = await runCli(["check", "--staged", "--format", "json"], {
    cwd: process.cwd(),
    collectDiff: () => vulnerableDiff,
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(writes.join(""));

  assert.equal(result.exitCode, 1);
  assert.equal(report.findings[0].ruleId, "js-eval");
  assert.equal(report.findings[0].blocking, true);
});

test("runCli defaults to full repository scan without diff collection", async () => {
  const writes: string[] = [];
  let diffCalled = false;
  const result = await runCli(["check", "--format", "json"], {
    cwd: process.cwd(),
    collectRepositoryFiles: () => [{
      path: "src/app.js",
      oldPath: "src/app.js",
      status: "modified",
      addedLines: [{ line: 1, content: "eval(req.body.code);" }],
      removedLines: []
    }],
    collectDiff: () => {
      diffCalled = true;
      return vulnerableDiff;
    },
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(writes.join(""));

  assert.equal(diffCalled, false);
  assert.equal(result.exitCode, 1);
  assert.equal(report.findings[0].ruleId, "js-eval");
});

test("runCli renders AI BOM JSON", async () => {
  const writes: string[] = [];
  const result = await runCli(["aibom", "--format", "aibom-json"], {
    cwd: process.cwd(),
    collectRepositoryFiles: () => [{
      path: "src/agent.ts",
      oldPath: "src/agent.ts",
      status: "modified",
      addedLines: [
        { line: 1, content: "const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });" }
      ],
      removedLines: [],
      allLines: [
        { line: 1, content: "const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });" }
      ]
    }],
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  const output = JSON.parse(writes.join(""));
  assert.equal(result.exitCode, 0);
  assert.equal(output.schemaVersion, "vibeguard.aibom.v1");
  assert.equal(output.summary.models, 1);
});

test("runCli defaults AI BOM to human console output", async () => {
  const writes: string[] = [];
  const result = await runCli(["aibom"], {
    cwd: process.cwd(),
    collectRepositoryFiles: () => [{
      path: "src/agent.ts",
      oldPath: "src/agent.ts",
      status: "modified",
      addedLines: [
        { line: 1, content: "const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });" }
      ],
      removedLines: [],
      allLines: [
        { line: 1, content: "const response = await openai.chat.completions.create({ model: 'gpt-4.1', messages });" }
      ]
    }],
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  const output = writes.join("");
  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("VIBEGUARD / AI BILL OF MATERIALS"), true);
  assert.equal(output.includes("Asset Register"), true);
});

test("runCli defaults agent graph to human console output", async () => {
  const writes: string[] = [];
  const result = await runCli(["graph"], {
    cwd: process.cwd(),
    collectRepositoryFiles: () => [{
      path: "src/agent.ts",
      oldPath: "src/agent.ts",
      status: "modified",
      addedLines: [
        { line: 1, content: "export const agent = createAgent({ name: 'support-agent', tools: [shellTool] });" },
        { line: 2, content: "const shellTool = { name: 'run_shell', execute: ({ command }) => exec(command) };" }
      ],
      removedLines: [],
      allLines: [
        { line: 1, content: "export const agent = createAgent({ name: 'support-agent', tools: [shellTool] });" },
        { line: 2, content: "const shellTool = { name: 'run_shell', execute: ({ command }) => exec(command) };" }
      ]
    }],
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  const output = writes.join("");
  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("VIBEGUARD / AGENT CAPABILITY GRAPH"), true);
  assert.equal(output.includes("Exposure Summary"), true);
});

test("runCli shows framework guidance when interactive mode has no TTY", async () => {
  const writes: string[] = [];
  const result = await runCli([], {
    cwd: process.cwd(),
    isTty: false,
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  const output = writes.join("");
  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("AI security CLI framework"), true);
  assert.equal(output.includes("vibeguard interactive"), true);
});

test("runCli starts the framework console with no arguments", async () => {
  const writes: string[] = [];
  const answers = ["", "doctor", "exit"];
  const result = await runCli([], {
    cwd: process.cwd(),
    prompt: async () => answers.shift() ?? "n",
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  const output = writes.join("");
  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("VibeGuard Framework"), true);
  assert.equal(output.includes("doctor"), true);
  assert.equal(output.includes("VibeGuard doctor"), true);
});

test("runCli setup prints installation and API key guidance", async () => {
  const writes: string[] = [];
  const result = await runCli(["setup"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const output = writes.join("");

  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("VIBEGUARD / SETUP GUIDE"), true);
  assert.equal(output.includes("Node.js 20+"), true);
  assert.equal(output.includes("vibeguard init"), true);
  assert.equal(output.includes("--vuln-provider osv"), true);
  assert.equal(output.includes("No OpenAI, Anthropic, Gemini, or LLM provider API key is required by VibeGuard"), true);
  assert.equal(output.includes("NPM_TOKEN"), true);
  assert.equal(output.includes("vibeguard doctor"), true);
});

test("runCli interactive setup command prints setup guide", async () => {
  const writes: string[] = [];
  const answers = ["", "setup", "exit"];
  const result = await runCli([], {
    cwd: process.cwd(),
    prompt: async () => answers.shift() ?? "exit",
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const output = writes.join("");

  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("setup"), true);
  assert.equal(output.includes("VIBEGUARD / SETUP GUIDE"), true);
});

test("runCli explain returns rule details", async () => {
  const writes: string[] = [];
  const result = await runCli(["explain", "js-eval"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  assert.equal(result.exitCode, 0);
  assert.equal(writes.join("").includes("Dynamic code execution"), true);
});

test("runCli explain includes enterprise rule metadata", async () => {
  const writes: string[] = [];
  const result = await runCli(["explain", "js-eval"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const output = writes.join("");

  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("Rule version: 2026.06.11"), true);
  assert.equal(output.includes("Framework mappings:"), true);
  assert.equal(output.includes("OWASP Top 10 for LLM Applications"), true);
});

test("runCli explain marks unmapped built-in rules stable", async () => {
  const writes: string[] = [];
  const result = await runCli(["explain", "docker-base-latest"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const output = writes.join("");

  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("Rule version: 2026.06.11"), true);
  assert.equal(output.includes("Rule stability: stable"), true);
  assert.equal(output.includes("Framework mappings:"), true);
  assert.equal(output.includes("- No framework mapping"), true);
  assert.equal(output.includes("Rule stability: custom"), false);
});

test("runCli explain covers AI model remote-code rule with enterprise mappings", async () => {
  const writes: string[] = [];
  const result = await runCli(["explain", "ai-model-trust-remote-code"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const output = writes.join("");

  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("Rule stability: stable"), true);
  assert.equal(
    output.includes("AI supply chain") || output.includes("OWASP Top 10 for LLM Applications"),
    true
  );
});

test("runCli explain covers unpinned Docker base image rule", async () => {
  const writes: string[] = [];
  const errors: string[] = [];
  const result = await runCli(["explain", "docker-base-unpinned"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: (text) => errors.push(text)
  });
  const output = writes.join("");

  assert.equal(result.exitCode, 0);
  assert.equal(output.includes("Rule stability: stable"), true);
  assert.equal(output.includes("No explanation found"), false);
  assert.equal(errors.join("").includes("No explanation found"), false);
});

test("runCli doctor reports local-first behavior", async () => {
  const writes: string[] = [];
  const result = await runCli(["doctor"], {
    cwd: process.cwd(),
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  assert.equal(result.exitCode, 0);
  assert.equal(writes.join("").includes("No source upload"), true);
});

test("runCli strict coverage exits when repository coverage is partial", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-strict-coverage-"));
  writeFileSync(join(cwd, "large.txt"), "x".repeat(20));
  const errors: string[] = [];
  const result = await runCli(["check", "--quiet", "--strict-coverage", "--max-file-bytes", "10"], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("Coverage incomplete"), true);
});

test("runCli rejects report output paths outside the working directory", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const outsidePath = `${cwd}-outside-report.html`;
  const errors: string[] = [];
  const result = await runCli(["report", "--output", outsidePath, "--quiet"], {
    cwd,
    collectRepositoryFiles: () => [],
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("--output must stay inside the working directory"), true);
  assert.equal(existsSync(outsidePath), false);
});

test("runCli creates nested output directories inside the working directory", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-output-"));
  const result = await runCli(["aibom", "--format", "aibom-json", "--output", "reports/aibom.json"], {
    cwd,
    collectRepositoryFiles: () => [],
    stdout: () => {},
    stderr: () => {}
  });

  assert.equal(result.exitCode, 0);
  assert.equal(existsSync(join(cwd, "reports", "aibom.json")), true);
});

test("runCli still rejects output directories outside the working directory", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-output-"));
  const errors: string[] = [];
  const result = await runCli(["aibom", "--format", "aibom-json", "--output", "../aibom.json"], {
    cwd,
    collectRepositoryFiles: () => [],
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("--output must stay inside the working directory"), true);
});

test("runCli rejects suppression config paths outside the working directory", async () => {
  const cwd = mkdtempSync(join(tmpdir(), "vibeguard-cli-"));
  const outsidePath = `${cwd}-outside-config.yml`;
  const errors: string[] = [];
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "accepted for migration",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-01-01",
    "--config",
    outsidePath
  ], {
    cwd,
    stdout: () => {},
    stderr: (text) => errors.push(text)
  });

  assert.equal(result.exitCode, 2);
  assert.equal(errors.join("").includes("--config must stay inside the working directory"), true);
  assert.equal(existsSync(outsidePath), false);
});
