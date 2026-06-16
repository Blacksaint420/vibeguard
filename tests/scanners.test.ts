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

test("AI scanner detects unsafe model supply chain flags", () => {
  const findings = runAiScanner([
    file("model.py", ["model = AutoModel.from_pretrained(model_id, trust_remote_code=True)"])
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, "ai-model-trust-remote-code");
  assert.equal(findings[0].severity, "critical");
});
