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
  matches(context: RuleContext): boolean;
  evidence: string;
  attackPath: string;
  impact: string;
  why: string;
  fix: string;
  test: string;
};

type RuleContext = {
  file: DiffFile;
  lineIndex: number;
  rawLine: string;
  strippedLine: string;
  rawText: string;
  strippedText: string;
};

type StripState = {
  inBlockComment: boolean;
  inTemplateLiteral: boolean;
  pythonTripleQuote?: "\"\"\"" | "'''";
};

const RULES: Rule[] = [
  {
    id: "ai-agent-shell-tool-no-approval",
    title: "Agent tool exposes shell execution without approval",
    severity: "critical",
    confidence: "high",
    riskScore: 96,
    owasp: owaspCategory("LLM06:2025"),
    matches: ({ strippedLine }) =>
      /\b(tools?|functions?)\s*:/.test(strippedLine) &&
      /\b(shell|terminal|command|exec|spawn|run_shell)\b/i.test(strippedLine) &&
      /\b(execute|handler|func|callback|exec|spawn)\b/i.test(strippedLine) &&
      !/\b(approval|requiredApproval|humanApproval|confirm|allowlist)\b/i.test(strippedLine),
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
    matches: ({ strippedLine }) =>
      (
        /\.\s*similaritySearch\s*\(\s*(query|input)\b/i.test(strippedLine) ||
        /\b[\w$]*(?:vector|embedding|retriever|rag|semantic|docStore|documentStore)[\w$]*\s*\.\s*(query|retrieve)\s*\(\s*(query|input)\b/i.test(strippedLine)
      ) &&
      !/\b(filter|where|tenant|namespace|metadata|authz|scope)\b/i.test(strippedLine),
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
    matches: ({ strippedLine }) =>
      /\b(max_tokens|max_completion_tokens|maxTokens|maxCompletionTokens|maxOutputTokens)\s*[:=]\s*(Infinity|[1-9]\d{4,})\b/i.test(strippedLine),
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
    matches: ({ strippedLine }) => /\btrust_remote_code\s*=\s*True\b/.test(strippedLine),
    evidence: "Model loading enables trust_remote_code=True.",
    attackPath: "Application loads a model artifact -> remote repository code executes during model initialization.",
    impact: "A malicious or compromised model repository can execute arbitrary code in the application environment.",
    why: "Model artifacts are part of the software supply chain; trusting remote code turns model loading into code execution.",
    fix: "Disable trust_remote_code, pin reviewed model revisions, and vendor or audit any required custom model code.",
    test: "Add a model-loading test or policy check proving trust_remote_code is false and model revisions are pinned."
  },
  {
    id: "ai-output-json-without-schema-validation",
    title: "LLM JSON output parsed without schema validation",
    severity: "high",
    confidence: "high",
    riskScore: 86,
    owasp: owaspCategory("LLM05:2025"),
    matches: ({ strippedLine, rawText, strippedText }) =>
      /\bJSON\.parse\s*\([^)]*(completion|response|message\.content|choices\s*\[|output_text|model|llm)/i.test(strippedLine) &&
      !hasSchemaValidation(rawText, strippedText),
    evidence: "Model output is parsed as JSON without visible schema validation or structured output enforcement.",
    attackPath: "Attacker influences model output -> application parses untrusted JSON -> downstream logic trusts attacker-shaped fields.",
    impact: "This can bypass business rules, authorization checks, or tool argument constraints that assume structured model output is trustworthy.",
    why: "LLM JSON output is untrusted data and needs schema validation before application logic consumes it.",
    fix: "Validate parsed model output with a schema, safe parser, function/tool schema, or provider structured-output contract.",
    test: "Add a test where malformed or adversarial model JSON is rejected before business logic runs."
  },
  {
    id: "ai-llm-call-without-timeout",
    title: "LLM call has no visible timeout or abort signal",
    severity: "high",
    confidence: "high",
    riskScore: 82,
    owasp: owaspCategory("LLM10:2025"),
    matches: ({ strippedLine, strippedText }) =>
      isLlmCall(strippedLine) &&
      !/\b(timeout|signal|AbortSignal|AbortController|withTimeout|deadline)\b/i.test(strippedText),
    evidence: "A provider LLM call has no visible timeout, abort signal, or timeout wrapper.",
    attackPath: "Caller triggers LLM path -> upstream call hangs or runs long -> request workers, queues, or rate limits are exhausted.",
    impact: "This can degrade availability and increase model spend during provider latency or adversarial traffic.",
    why: "LLM calls should have bounded execution time so one request cannot consume runtime resources indefinitely.",
    fix: "Add a request timeout, abort signal, client timeout option, or wrapper enforcing a deadline around the LLM call.",
    test: "Add a test proving slow model calls are cancelled and return a controlled error."
  },
  {
    id: "ai-llm-call-without-rate-limit",
    title: "User-facing LLM endpoint has no visible rate limit or quota",
    severity: "medium",
    confidence: "medium",
    riskScore: 72,
    owasp: owaspCategory("LLM10:2025"),
    matches: ({ strippedLine, strippedText }) =>
      isUserFacingEndpoint(strippedText) &&
      isLlmCall(strippedLine) &&
      !/\b(rateLimit|rateLimiter|throttle|quota|limitByUser|requireAuth|authMiddleware|middleware|guard)\b/i.test(strippedText),
    evidence: "A user-facing route invokes an LLM without visible rate-limit, auth quota, or throttle evidence.",
    attackPath: "Unauthenticated or unthrottled caller repeatedly hits the endpoint -> model calls scale with attacker traffic.",
    impact: "This can create cost spikes, latency degradation, and denial of service through model consumption.",
    why: "User-triggered LLM endpoints need rate limits or quotas because every request can consume scarce model capacity.",
    fix: "Add per-user or per-tenant rate limiting, authenticated quotas, and abuse monitoring around the LLM endpoint.",
    test: "Add a route test proving repeated requests are throttled before an LLM call is made."
  },
  {
    id: "ai-llm-call-without-cost-tracking",
    title: "User-triggered LLM call lacks visible usage or cost tracking",
    severity: "medium",
    confidence: "medium",
    riskScore: 66,
    owasp: owaspCategory("LLM10:2025"),
    matches: ({ strippedLine, strippedText }) =>
      isLlmCall(strippedLine) &&
      /\b(req\.|request\.|ctx\.request|body|query|params)\b/i.test(strippedLine) &&
      !/\b(usage|total_tokens|prompt_tokens|completion_tokens|cost|meter|billing|quota|recordUsage|trackUsage|tokenCount)\b/i.test(strippedText),
    evidence: "A request-triggered LLM call has no visible token, usage, cost, or quota accounting.",
    attackPath: "Caller reaches repeated model calls -> application does not meter usage -> abnormal consumption is hard to detect or control.",
    impact: "This can hide spend abuse and delay response to model-consumption incidents.",
    why: "Enterprise LLM paths need usage accounting so teams can detect abuse, assign cost, and enforce quotas.",
    fix: "Record model usage, token counts, request owner, and cost metadata for user-triggered LLM calls.",
    test: "Add a test proving successful and failed model calls emit usage or quota accounting events."
  },
  {
    id: "ai-prompt-template-interpolates-user-input",
    title: "Prompt template interpolates user-controlled input",
    severity: "high",
    confidence: "high",
    riskScore: 84,
    owasp: owaspCategory("LLM01:2025"),
    matches: ({ rawLine }) =>
      /`[^`]*\$\{[^}]*\b(req\.|request\.|ctx\.request|body|query|params|userInput|input)\b[^}]*\}[^`]*`/.test(rawLine) &&
      !/\b(delimit|sanitize|escapePrompt|stripInstructions|asUserContent|trustedInput)\b/i.test(rawLine),
    evidence: "A prompt template interpolates request or user-controlled input without visible delimiter or sanitizer handling.",
    attackPath: "Attacker controls interpolated prompt text -> injected instructions blend into trusted prompt context -> model follows attacker intent.",
    impact: "This can bypass prompt controls, alter generated output, or steer downstream tool use.",
    why: "Prompt templates should separate instructions from user data and delimit or sanitize untrusted content.",
    fix: "Pass user content as a separate message or delimit and sanitize it before interpolation.",
    test: "Add a prompt-injection test proving user input cannot override the surrounding template instructions."
  },
  {
    id: "ai-system-prompt-logged",
    title: "System or developer prompt is logged",
    severity: "high",
    confidence: "high",
    riskScore: 82,
    owasp: owaspCategory("LLM07:2025"),
    matches: ({ strippedLine }) =>
      /\b(console\.(log|warn|error|info)|logger\.(debug|info|warn|error)|telemetry\.|trace\.|span\.|captureException|Sentry\.)\s*\([^)]*(systemPrompt|SYSTEM_PROMPT|developerPrompt|guardrailPrompt)/i.test(strippedLine),
    evidence: "A system, developer, or guardrail prompt variable is sent to logs, telemetry, tracing, or error capture.",
    attackPath: "Prompt text is written to observability storage -> operators, compromised logs, or support exports expose privileged instructions.",
    impact: "Leaked prompts can reveal policy logic, hidden instructions, or sensitive context used to protect the AI system.",
    why: "Privileged prompts are sensitive operational data and should not be logged verbatim.",
    fix: "Log prompt identifiers or versions instead of full prompt text, and redact prompt content from telemetry.",
    test: "Add a logging test proving prompt variables are redacted or replaced with prompt IDs."
  },
  {
    id: "ai-rag-upsert-untrusted-content",
    title: "Untrusted content is inserted into a vector store",
    severity: "high",
    confidence: "high",
    riskScore: 86,
    owasp: owaspCategory("LLM04:2025"),
    matches: ({ strippedLine, strippedText }) =>
      /\b(?:vectorStore|embedding|retriever|docStore|documentStore|index)[\w$]*\s*\.\s*(upsert|addDocuments|addVectors|insert)\s*\([^;\n]*(req\.|request\.|ctx\.request|body|query|params|userInput|input)/i.test(strippedLine) &&
      /\b(vectorStore|vector|embedding|retriever|docStore|documentStore|index)\b/i.test(strippedText) &&
      !/\b(moderat|trusted|reviewed|approved|provenance|sourceVerified|quarantine|sanitize)\b/i.test(strippedText),
    evidence: "Request or user-controlled content is embedded or inserted into retrieval storage without visible trust, moderation, or review evidence.",
    attackPath: "Attacker submits content -> content is indexed into RAG corpus -> later retrieval injects attacker-controlled context into model prompts.",
    impact: "This can poison RAG answers, persist prompt injection, or expose downstream users to malicious context.",
    why: "RAG ingestion needs provenance, trust marking, moderation, or review before untrusted content enters retrieval paths.",
    fix: "Moderate and mark provenance for ingested content, quarantine untrusted submissions, and restrict retrieval to trusted documents.",
    test: "Add an ingestion test proving untrusted documents are rejected, quarantined, or marked untrusted before indexing."
  },
  {
    id: "ai-rag-client-controlled-filter",
    title: "RAG query uses client-controlled filter or namespace",
    severity: "high",
    confidence: "high",
    riskScore: 84,
    owasp: owaspCategory("LLM08:2025"),
    matches: ({ strippedLine }) =>
      /\b(similaritySearch|query|retrieve|search)\s*\([^)]*\b(filter|where|namespace|metadata)\s*:\s*(req\.|request\.|ctx\.request|body|query|params)/i.test(strippedLine),
    evidence: "A vector search filter, namespace, where clause, or metadata constraint is derived from client-controlled request data.",
    attackPath: "Attacker supplies retrieval filter -> vector store searches unauthorized namespace or metadata scope -> restricted documents enter model context.",
    impact: "This can disclose cross-tenant or restricted documents through generated answers.",
    why: "RAG filters should be derived from server-side authorization context, not raw client input.",
    fix: "Build filters from authenticated tenant, role, and document authorization context on the server.",
    test: "Add a retrieval test proving callers cannot select another tenant, namespace, or restricted metadata filter."
  },
  {
    id: "ai-mcp-config-dangerous-server",
    title: "MCP config exposes dangerous server without scope metadata",
    severity: "high",
    confidence: "high",
    riskScore: 88,
    owasp: owaspCategory("LLM06:2025"),
    matches: ({ file, rawLine }) =>
      isMcpConfigPath(file.path) &&
      /\b(filesystem|shell|browser|playwright|puppeteer|postgres|sqlite|mysql|database|aws|gcp|azure|secrets?|keychain)\b/i.test(rawLine) &&
      !/\b(scope|roots|allowedDirectories|allowlist|readOnly|permissions|sandbox|approval)\b/i.test(rawLine),
    evidence: "An MCP configuration references a filesystem, shell, browser, database, cloud, or secret-bearing server without visible scope metadata.",
    attackPath: "Agent connects to broad MCP server -> model-selected tool calls reach sensitive local or cloud capabilities.",
    impact: "This can expand agent authority to files, browsers, databases, cloud accounts, or secrets without review boundaries.",
    why: "Dangerous MCP servers need explicit scope, permissions, sandboxing, or approval metadata.",
    fix: "Add scoped roots, read-only settings, allowlists, sandboxing, and approval requirements to MCP server configuration.",
    test: "Add a config test proving dangerous MCP servers declare scoped permissions before use."
  },
  {
    id: "ai-tool-broad-input-schema",
    title: "Agent tool accepts broad free-form input",
    severity: "high",
    confidence: "high",
    riskScore: 86,
    owasp: owaspCategory("LLM06:2025"),
    matches: ({ strippedLine }) =>
      !/^\s*function\s+[A-Za-z_$][\w$]*\s*\(/.test(strippedLine) &&
      (
        /\b([\w$]*Tool|tools?)\b/i.test(strippedLine) ||
        /\bfunctions?\s*:\s*\[/.test(strippedLine) ||
        /\bparameters\s*:/.test(strippedLine) ||
        /\binputSchema\s*:/.test(strippedLine)
      ) &&
      /\b(command|path|url|query)\b/i.test(strippedLine) &&
      /\b(z\.string\s*\(\)|type\s*:\s*string|string\s*\})/i.test(strippedLine) &&
      !/\b(enum|literal|allowlist|whitelist|regex|urlAllowlist|pathAllowlist|choices)\b/i.test(strippedLine),
    evidence: "An agent tool schema exposes command, path, URL, or query input as an unconstrained string.",
    attackPath: "Attacker influences tool arguments -> model emits broad string input -> tool receives command/path/URL/query outside intended bounds.",
    impact: "This can enable command injection, path traversal, SSRF, data overreach, or unintended tool actions.",
    why: "High-risk tool arguments need structured constraints instead of free-form model-generated strings.",
    fix: "Use enums, literals, allowlists, strict regexes, or server-side argument builders for dangerous tool inputs.",
    test: "Add a tool-schema test proving disallowed command, path, URL, or query values are rejected."
  },
  {
    id: "ai-model-revision-unpinned",
    title: "Model artifact revision is not pinned",
    severity: "high",
    confidence: "high",
    riskScore: 86,
    owasp: owaspCategory("LLM03:2025"),
    matches: ({ rawLine, strippedLine }) =>
      /\b(from_pretrained|snapshot_download)\s*\(\s*["'][^"']+["']/i.test(rawLine) &&
      !/\b(revision|commit_hash|commit|sha)\s*=/.test(strippedLine) &&
      !/\btrust_remote_code\s*=\s*True\b/.test(strippedLine),
    evidence: "A model artifact is loaded from a repository without a pinned revision or commit.",
    attackPath: "Application loads model by mutable name -> upstream artifact changes -> unreviewed model or code enters runtime.",
    impact: "This can introduce compromised, regressed, or unapproved model artifacts without code review.",
    why: "Model artifacts are supply-chain inputs and should be pinned to reviewed immutable revisions.",
    fix: "Pin model loads to a reviewed revision or commit hash and track model provenance in release metadata.",
    test: "Add a model-loading test proving repository models specify an immutable revision."
  }
];

export function runAiScanner(files: DiffFile[]): Finding[] {
  const findings: Finding[] = [];

  for (const file of files) {
    if (isVendoredOrGeneratedPath(file.path)) continue;
    if (!isAiScannableFile(file.path)) continue;

    const addedLineNumbers = new Set(file.addedLines.map((line) => line.line));
    const linesToScan = file.allLines ?? file.addedLines;
    const rawText = linesToScan.map((line) => line.content).join("\n");
    const stripState: StripState = { inBlockComment: false, inTemplateLiteral: false };
    const strippedLines = linesToScan.map((line) => stripStringsAndComments(line.content, file.path, stripState));
    const strippedText = strippedLines.join("\n");
    for (const line of linesToScan) {
      const lineIndex = linesToScan.findIndex((candidate) => candidate.line === line.line);
      const strippedLine = strippedLines[lineIndex] ?? "";
      if (!addedLineNumbers.has(line.line)) continue;
      if (!strippedLine.trim()) continue;
      const context: RuleContext = {
        file,
        lineIndex,
        rawLine: line.content,
        strippedLine,
        rawText,
        strippedText
      };
      for (const rule of RULES) {
        if (!rule.matches(context)) continue;
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

function isAiScannableFile(path: string): boolean {
  return isJavaScriptFile(path) || isPythonFile(path) || isMcpConfigPath(path) || /\.(json|ya?ml)$/.test(path);
}

function isMcpConfigPath(path: string): boolean {
  return /(^|\/)(\.cursor\/mcp\.json|\.mcp\.json|mcp\.json|claude_desktop_config\.json|agent\.json|agents\.json|agent-config\.json)$/i.test(path);
}

function isLlmCall(line: string): boolean {
  return /\b(openai\.(chat\.completions|responses|embeddings)\.create|anthropic\.messages\.create|generateContent\s*\(|invokeModel\s*\(|bedrock\.|model\.invoke\s*\(|llm\.invoke\s*\()/i.test(line);
}

function isUserFacingEndpoint(text: string): boolean {
  return /\b(app|router)\.(get|post|put|patch|delete)\s*\(|export\s+async\s+function\s+(GET|POST|PUT|PATCH)|NextRequest|RequestHandler|req\.|request\./i.test(text);
}

function hasSchemaValidation(rawText: string, strippedText: string): boolean {
  return /\b(safeParse|parseAsync|validate|schema\.parse|zod|TypeBox|ajv|json_schema|response_format|tool_choice|function_call|tools\s*:|functions\s*:)\b/i.test(rawText) ||
    /\b(safeParse|parseAsync|validate|schema\.parse|response_format|tool_choice|function_call|tools\s*:|functions\s*:)\b/i.test(strippedText);
}

function stripStringsAndComments(line: string, path: string, state: StripState): string {
  let output = "";
  let index = 0;
  const isJavaScript = isJavaScriptFile(path);

  while (index < line.length) {
    const char = line[index];
    const next = line[index + 1];

    if (state.inBlockComment) {
      const end = line.indexOf("*/", index);
      if (end === -1) return output;
      output += " ".repeat(end + 2 - index);
      index = end + 2;
      state.inBlockComment = false;
      continue;
    }

    if (state.pythonTripleQuote) {
      const end = line.indexOf(state.pythonTripleQuote, index);
      if (end === -1) return output;
      output += " ".repeat(end + state.pythonTripleQuote.length - index);
      index = end + state.pythonTripleQuote.length;
      state.pythonTripleQuote = undefined;
      continue;
    }

    if (state.inTemplateLiteral) {
      const end = findTemplateLiteralEnd(line, index);
      if (end === -1) return output;
      output += " ".repeat(end + 1 - index);
      index = end + 1;
      state.inTemplateLiteral = false;
      continue;
    }

    if (isJavaScript && char === "/" && next === "/") break;
    if (isJavaScript && char === "/" && next === "*") {
      const end = line.indexOf("*/", index + 2);
      if (end === -1) {
        state.inBlockComment = true;
        break;
      }
      output += " ".repeat(end + 2 - index);
      index = end + 2;
      continue;
    }
    if (!isJavaScript && char === "#") break;

    if (!isJavaScript && (line.startsWith('"""', index) || line.startsWith("'''", index))) {
      const quote = line.slice(index, index + 3) as StripState["pythonTripleQuote"];
      const end = line.indexOf(quote, index + 3);
      if (end === -1) {
        state.pythonTripleQuote = quote;
        break;
      }
      output += " ".repeat(end + 3 - index);
      index = end + 3;
      continue;
    }

    if (isJavaScript && char === "`") {
      const end = findTemplateLiteralEnd(line, index + 1);
      if (end === -1) {
        state.inTemplateLiteral = true;
        break;
      }
      output += " ".repeat(end + 1 - index);
      index = end + 1;
      continue;
    }

    if (char === "\"" || char === "'") {
      const { end, inner } = readStringLiteral(line, index, char);
      const nextMeaningful = nextNonWhitespace(line, end + 1);
      if (nextMeaningful === ":" && isPlausibleObjectKey(line, index)) {
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

function findTemplateLiteralEnd(line: string, start: number): number {
  let escaped = false;
  for (let index = start; index < line.length; index += 1) {
    const char = line[index];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (char === "\\") {
      escaped = true;
      continue;
    }
    if (char === "`") return index;
  }
  return -1;
}

function nextNonWhitespace(line: string, start: number): string | undefined {
  for (let index = start; index < line.length; index += 1) {
    if (!/\s/.test(line[index])) return line[index];
  }
  return undefined;
}

function isPlausibleObjectKey(line: string, stringStart: number): boolean {
  for (let index = stringStart - 1; index >= 0; index -= 1) {
    if (/\s/.test(line[index])) continue;
    return line[index] === "{" || line[index] === ",";
  }
  return true;
}
