import test from "node:test";
import assert from "node:assert/strict";

import { runCodeScanner } from "../packages/scanners/src/code.ts";
import { runSecretScanner, maskSecretValue } from "../packages/scanners/src/secrets.ts";
import { runDependencyScanner } from "../packages/scanners/src/dependencies.ts";
import { runDockerfileScanner } from "../packages/scanners/src/docker.ts";
import { runActionsScanner } from "../packages/scanners/src/actions.ts";
import { runSensitiveFileScanner } from "../packages/scanners/src/sensitive-files.ts";
import { runAiScanner } from "../packages/scanners/src/ai.ts";

function file(path: string, lines: string[], removedLines: string[] = []) {
  return {
    path,
    oldPath: path,
    status: "modified",
    addedLines: lines.map((content, index) => ({ line: index + 1, content })),
    removedLines: removedLines.map((content, index) => ({ line: index + 1, content }))
  };
}

function fileWithContext(path: string, addedLineNumbers: number[], allLines: string[]) {
  return {
    path,
    oldPath: path,
    status: "modified",
    addedLines: addedLineNumbers.map((line) => ({ line, content: allLines[line - 1] })),
    removedLines: [],
    allLines: allLines.map((content, index) => ({ line: index + 1, content }))
  };
}

test("code scanner finds high-confidence JavaScript and Python issues", () => {
  const findings = [
    ...runCodeScanner([file("src/app.js", ["eval(req.body.code);"])]),
    ...runCodeScanner([file("app.py", ["requests.get(url, verify=False)"])])
  ];

  assert.deepEqual(findings.map((finding) => finding.ruleId).sort(), [
    "js-eval",
    "py-requests-verify-false"
  ]);
  assert.equal(findings.every((finding) => finding.aiFixPrompt.length > 20), true);
});

test("secret scanner masks detected tokens", () => {
  const githubToken = ["ghp_1234567890", "abcdefghijklmnopqrstuvwxyz1234"].join("");
  const masked = maskSecretValue(githubToken);
  const findings = runSecretScanner([
    file(".env", [`GITHUB_TOKEN=${githubToken}`])
  ]);

  assert.equal(masked.includes("abcdefghijklmnopqrstuvwxyz"), false);
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "secret-github-token");
  assert.equal(findings[0].snippet.includes("abcdefghijklmnopqrstuvwxyz"), false);
});

test("dependency scanner reports broad ranges, downgrades, and lockfile-only changes", () => {
  const findings = runDependencyScanner([
    file("package.json", ['"dependencies": {', '"express": "^4.18.0"', "}"]),
    file("requirements.txt", ["django==3.2.0"], ["django==5.0.0"]),
    file("pnpm-lock.yaml", ["lockfileVersion: '9.0'"])
  ]);

  assert.equal(findings.some((finding) => finding.ruleId === "dep-broad-version-range"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "dep-version-downgrade"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "dep-lockfile-without-manifest"), false);

  const lockOnly = runDependencyScanner([
    file("package-lock.json", ['"lockfileVersion": 3'])
  ]);

  assert.equal(lockOnly.some((finding) => finding.ruleId === "dep-lockfile-without-manifest"), true);
});

test("docker and GitHub Actions scanners find mutable component references", () => {
  const dockerFindings = runDockerfileScanner([file("Dockerfile", ["FROM node:latest"])]);
  const actionFindings = runActionsScanner([
    file(".github/workflows/ci.yml", ["uses: actions/checkout@v4", "permissions: write-all"])
  ]);

  assert.equal(dockerFindings[0].ruleId, "docker-base-latest");
  assert.equal(actionFindings.some((finding) => finding.ruleId === "gha-mutable-action-ref"), true);
  assert.equal(actionFindings.some((finding) => finding.ruleId === "gha-write-all-permissions"), true);
});

test("sensitive file scanner reports risky file path changes", () => {
  const findings = runSensitiveFileScanner([
    file(".npmrc", ["//registry.npmjs.org/:_authToken=npm_secret"])
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "sensitive-file-change");
  assert.equal(findings[0].severity, "high");
});

test("AI scanner detects unsafe agent tool and RAG patterns", () => {
  const findings = runAiScanner([
    file("src/agent.ts", [
      'tools: [{ name: "run_shell", execute: ({ command }) => exec(command) }]',
      "await vectorStore.similaritySearch(query, 50);",
      "const result = await openai.chat.completions.create({ messages, max_tokens: 100000 });"
    ])
  ]);

  assert.deepEqual(findings.map((finding) => finding.ruleId).sort(), [
    "ai-agent-shell-tool-no-approval",
    "ai-rag-query-without-filter",
    "ai-unbounded-token-request"
  ]);
});

test("AI scanner ignores comments and string literals", () => {
  const findings = runAiScanner([
    file("src/notes.ts", [
      '// tools: [{ name: "run_shell", execute: ({ command }) => exec(command) }]',
      'const example = "tools: [{ name: \\"run_shell\\", execute: ({ command }) => exec(command) }]";',
      'const tokenExample = "max_tokens: 100000";',
      'const ragExample = "vectorStore.similaritySearch(query, 50)";'
    ]),
    file("model.py", [
      "# model = AutoModel.from_pretrained(model_id, trust_remote_code=True)",
      'example = "trust_remote_code=True"'
    ])
  ]);

  assert.equal(findings.length, 0);
});

test("AI scanner ignores multiline comments and Python triple-quoted strings", () => {
  const findings = runAiScanner([
    file("src/commented-agent.ts", [
      "/*",
      'tools: [{ name: "run_shell", execute: () => exec(command) }]',
      "*/"
    ]),
    file("model.py", [
      '"""',
      "model = AutoModel.from_pretrained(model_id, trust_remote_code=True)",
      '"""'
    ])
  ]);

  assert.equal(findings.length, 0);
});

test("AI scanner uses full context for added lines inside existing JavaScript block comments", () => {
  const findings = runAiScanner([
    fileWithContext("src/commented-agent.ts", [2], [
      "/*",
      'tools: [{ name: "run_shell", execute: () => exec(command) }]',
      "*/"
    ])
  ]);

  assert.equal(findings.length, 0);
});

test("AI scanner uses full context for added lines inside existing Python triple-quoted strings", () => {
  const findings = runAiScanner([
    fileWithContext("model.py", [2], [
      '"""',
      "model = AutoModel.from_pretrained(model_id, trust_remote_code=True)",
      '"""'
    ])
  ]);

  assert.equal(findings.length, 0);
});

test("AI scanner ignores multiline JavaScript template literals", () => {
  const findings = runAiScanner([
    file("src/template.ts", [
      "const fixture = `",
      'tools: [{ name: "run_shell", execute: () => exec(command) }]',
      "await vectorStore.similaritySearch(query, 50);",
      "`;"
    ])
  ]);

  assert.equal(findings.length, 0);
});

test("AI scanner uses full context for added lines inside existing JavaScript template literals", () => {
  const findings = runAiScanner([
    fileWithContext("src/template.ts", [2], [
      "const fixture = `",
      'tools: [{ name: "run_shell", execute: () => exec(command) }]',
      "`;"
    ])
  ]);

  assert.equal(findings.length, 0);
});

test("AI scanner reports positive findings when full context is present", () => {
  const findings = runAiScanner([
    fileWithContext("src/agent.ts", [2], [
      "export const tools = [",
      'tools: [{ name: "run_shell", execute: () => exec(command) }]',
      "];"
    ])
  ]);

  assert.deepEqual(findings.map((finding) => finding.ruleId), ["ai-agent-shell-tool-no-approval"]);
});

test("AI scanner limits RAG query detection to vector and retriever contexts", () => {
  const findings = runAiScanner([
    file("src/search.ts", [
      "await db.query(input);",
      "await retriever.query(input);"
    ])
  ]);

  assert.deepEqual(findings.map((finding) => finding.ruleId), ["ai-rag-query-without-filter"]);
});

test("AI scanner detects unsafe model supply chain flags", () => {
  const findings = runAiScanner([
    file("model.py", ["model = AutoModel.from_pretrained(model_id, trust_remote_code=True)"])
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "ai-model-trust-remote-code");
  assert.equal(findings[0].severity, "critical");
});
