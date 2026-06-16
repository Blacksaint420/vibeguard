import type { DiffFile, Finding } from "../../core/src/types.ts";
import { owaspCategory } from "../../core/src/owasp.ts";
import { maskSecretsInText } from "./secrets.ts";
import { isJavaScriptFile, isPythonFile, isVendoredOrGeneratedPath, scannerFinding } from "./utils.ts";

type Rule = {
  id: string;
  title: string;
  severity: "low" | "medium" | "high" | "critical";
  confidence: "low" | "medium" | "high";
  riskScore: number;
  owasp: ReturnType<typeof owaspCategory>;
  matches(line: string): boolean;
  evidence: string;
  attackPath: string;
  impact: string;
  why: string;
  fix: string;
  test: string;
};

const RULES: Rule[] = [
  {
    id: "ai-agent-shell-tool-no-approval",
    title: "Agent tool exposes shell execution without approval",
    severity: "critical",
    confidence: "high",
    riskScore: 96,
    owasp: owaspCategory("LLM06:2025"),
    matches: (line) =>
      /\b(tools?|functions?)\s*:/.test(line) &&
      /\b(shell|terminal|command|exec|spawn|run_shell)\b/i.test(line) &&
      /\b(execute|handler|func|callback|exec|spawn)\b/i.test(line) &&
      !/\b(approval|requiredApproval|humanApproval|confirm|allowlist)\b/i.test(line),
    evidence: "An agent tool registration exposes shell, command, exec, spawn, or terminal capability without an approval guard.",
    attackPath: "Attacker influences agent instructions -> model selects a shell-capable tool -> application executes the generated command.",
    impact: "This can allow autonomous command execution in the application or CI runtime.",
    why: "Agent tools that expose shell execution need explicit approval and constrained arguments because model-selected tool calls are attacker-influenceable.",
    fix: "Remove shell-capable agent tools or require human approval, strict command allowlists, and structured arguments before execution.",
    test: "Add a test proving shell-capable tools reject model-supplied commands unless an approval token and allowlisted command are present."
  },
  {
    id: "ai-rag-query-without-filter",
    title: "RAG retrieval query has no visible authorization filter",
    severity: "high",
    confidence: "medium",
    riskScore: 78,
    owasp: owaspCategory("LLM08:2025"),
    matches: (line) =>
      (
        /\.\s*similaritySearch\s*\(\s*(query|input)\b/i.test(line) ||
        /\b[\w$]*(?:vector|embedding|retriever|rag|semantic|docStore|documentStore)[\w$]*\s*\.\s*(query|retrieve)\s*\(\s*(query|input)\b/i.test(line)
      ) &&
      !/\b(filter|where|tenant|namespace|metadata|authz|scope)\b/i.test(line),
    evidence: "A RAG retrieval call uses query or input without an obvious filter, tenant scope, namespace, or metadata constraint.",
    attackPath: "Caller submits a query -> retriever searches broadly -> unauthorized documents can be returned into model context.",
    impact: "This can expose cross-tenant, restricted, or unrelated documents through generated answers.",
    why: "RAG retrieval should be scoped by server-side authorization context so user queries cannot search across protected document boundaries.",
    fix: "Add a server-derived metadata filter, tenant namespace, or authorization scope to the retrieval call.",
    test: "Add a retrieval test proving a user cannot retrieve documents from another tenant or restricted collection."
  },
  {
    id: "ai-unbounded-token-request",
    title: "LLM request uses excessive token budget",
    severity: "medium",
    confidence: "high",
    riskScore: 68,
    owasp: owaspCategory("LLM10:2025"),
    matches: (line) =>
      /\b(max_tokens|max_completion_tokens|maxTokens|maxCompletionTokens|maxOutputTokens)\s*[:=]\s*(Infinity|[1-9]\d{4,})\b/i.test(line),
    evidence: "An LLM request sets max_tokens, maxTokens, or a related token budget to 10000 or more, or Infinity.",
    attackPath: "Caller reaches the LLM path -> request allows excessive generation -> model consumes large token volume.",
    impact: "This can increase cost, latency, and rate-limit pressure enough to degrade availability.",
    why: "LLM token budgets should have practical server-side ceilings instead of unbounded or extreme per-request limits.",
    fix: "Clamp token budgets to a documented maximum appropriate for the use case and reject Infinity or unusually high values.",
    test: "Add a test proving token budgets above the service ceiling are rejected or clamped before the model call."
  },
  {
    id: "ai-model-trust-remote-code",
    title: "Model loading trusts remote code",
    severity: "critical",
    confidence: "high",
    riskScore: 98,
    owasp: owaspCategory("LLM03:2025"),
    matches: (line) => /\btrust_remote_code\s*=\s*True\b/.test(line),
    evidence: "Model loading enables trust_remote_code=True.",
    attackPath: "Application loads a model artifact -> remote repository code executes during model initialization.",
    impact: "A malicious or compromised model repository can execute arbitrary code in the application environment.",
    why: "Model artifacts are part of the software supply chain; trusting remote code turns model loading into code execution.",
    fix: "Disable trust_remote_code, pin reviewed model revisions, and vendor or audit any required custom model code.",
    test: "Add a model-loading test or policy check proving trust_remote_code is false and model revisions are pinned."
  }
];

export function runAiScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (isVendoredOrGeneratedPath(file.path)) continue;
    if (!isJavaScriptFile(file.path) && !isPythonFile(file.path)) continue;

    for (const line of file.addedLines) {
      const matchTarget = stripStringsAndComments(line.content, file.path);
      if (!matchTarget.trim()) continue;
      for (const rule of RULES) {
        if (!rule.matches(matchTarget)) continue;
        findings.push(scannerFinding({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          confidence: rule.confidence,
          riskScore: rule.riskScore,
          file: file.path,
          line: line.line,
          snippet: maskSecretsInText(line.content),
          owasp: rule.owasp,
          evidence: rule.evidence,
          attackPath: rule.attackPath,
          impact: rule.impact,
          why: rule.why,
          suggestedFix: rule.fix,
          testSuggestion: rule.test
        }));
      }
    }
  }

  return findings;
}

function stripStringsAndComments(line: string, path: string): string {
  let output = "";
  let index = 0;
  const isJavaScript = isJavaScriptFile(path);

  while (index < line.length) {
    const char = line[index];
    const next = line[index + 1];

    if (isJavaScript && char === "/" && next === "/") break;
    if (isJavaScript && char === "/" && next === "*") {
      const end = line.indexOf("*/", index + 2);
      if (end === -1) break;
      output += " ".repeat(end + 2 - index);
      index = end + 2;
      continue;
    }
    if (!isJavaScript && char === "#") break;

    if (char === "\"" || char === "'" || (isJavaScript && char === "`")) {
      const { end, inner } = readStringLiteral(line, index, char);
      const nextMeaningful = nextNonWhitespace(line, end + 1);
      if (char !== "`" && nextMeaningful === ":") {
        output += inner;
      } else {
        output += " ".repeat(end + 1 - index);
      }
      index = end + 1;
      continue;
    }

    output += char;
    index += 1;
  }

  return output;
}

function readStringLiteral(line: string, start: number, quote: string): { end: number; inner: string } {
  let escaped = false;
  let inner = "";

  for (let index = start + 1; index < line.length; index += 1) {
    const char = line[index];
    if (escaped) {
      escaped = false;
      inner += " ";
      continue;
    }
    if (char === "\\") {
      escaped = true;
      inner += " ";
      continue;
    }
    if (char === quote) {
      return { end: index, inner };
    }
    inner += char;
  }

  return { end: line.length - 1, inner };
}

function nextNonWhitespace(line: string, start: number): string | undefined {
  for (let index = start; index < line.length; index += 1) {
    if (!/\s/.test(line[index])) return line[index];
  }
  return undefined;
}
